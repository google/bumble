// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// L2CAP CoC server bridge: waits for a peer to connect an L2CAP CoC channel
/// on a specified PSM. When the connection is made, the bridge connects a TCP
/// socket to a remote host and bridges the data in both directions, with flow
/// control.
/// When the L2CAP CoC channel is closed, the bridge disconnects the TCP socket
/// and waits for a new L2CAP CoC channel to be connected.
/// When the TCP connection is closed by the TCP server, the L2CAP connection is closed as well.
use crate::cli::l2cap::{proxy_l2cap_rx_to_tcp_tx, proxy_tcp_rx_to_l2cap_tx, BridgeData};
use bumble::wrapper::{device::Device, hci::HciConstant, l2cap::LeConnectionOrientedChannel};
use futures::executor::block_on;
use owo_colors::OwoColorize;
use pyo3::{PyResult, Python};
use std::{sync::Arc, time::Duration};
use tokio::{
    join,
    net::TcpStream,
    select,
    sync::{mpsc, Mutex},
};

pub struct Args {
    pub psm: u16,
    pub max_credits: Option<u16>,
    pub mtu: Option<u16>,
    pub mps: Option<u16>,
    pub tcp_host: String,
    pub tcp_port: u16,
}

pub async fn start(args: &Args, device: &mut Device) -> PyResult<()> {
    let host = args.tcp_host.clone();
    let port = args.tcp_port;
    device.register_l2cap_channel_server(
        args.psm,
        move |py, l2cap_channel| {
            let channel_info = l2cap_channel
                .debug_string()
                .unwrap_or_else(|e| format!("failed to get l2cap channel info ({e})"));
            println!("{} {channel_info}", "*** L2CAP channel:".cyan());

            let host = host.clone();
            // Handles setting up a tokio runtime that runs this future to completion while also
            // containing the necessary context vars.
            pyo3_asyncio::tokio::future_into_py(
                py,
                proxy_data_between_l2cap_and_tcp(l2cap_channel, host, port),
            )?;
            Ok(())
        },
        args.max_credits,
        args.mtu,
        args.mps,
    )?;

    println!(
        "{}",
        format!("### Listening for CoC connection on PSM {}", args.psm).yellow()
    );

    device.on_connection(|_py, mut connection| {
        let connection_info = connection
            .debug_string()
            .unwrap_or_else(|e| format!("failed to get connection info ({e})"));
        println!(
            "{} {}",
            "@@@ Bluetooth connection: ".green(),
            connection_info,
        );
        connection.on_disconnection(|_py, reason| {
            let disconnection_info = match HciConstant::error_name(reason) {
                Ok(info_string) => info_string,
                Err(py_err) => format!("failed to get disconnection error name ({})", py_err),
            };
            println!(
                "{} {}",
                "@@@ Bluetooth disconnection: ".red(),
                disconnection_info,
            );
            Ok(())
        })?;
        Ok(())
    })?;

    device.start_advertising(false).await?;

    Ok(())
}

async fn proxy_data_between_l2cap_and_tcp(
    mut l2cap_channel: LeConnectionOrientedChannel,
    tcp_host: String,
    tcp_port: u16,
) -> PyResult<()> {
    let (l2cap_to_tcp_tx, mut l2cap_to_tcp_rx) = mpsc::channel::<BridgeData>(10);

    // Set callback (`set_sink`) for when l2cap data is received.
    let l2cap_to_tcp_tx_clone = l2cap_to_tcp_tx.clone();
    l2cap_channel
        .set_sink(move |_py, sdu| {
            block_on(l2cap_to_tcp_tx_clone.send(BridgeData::Data(sdu.into())))
                .expect("failed to channel data to tcp");
            Ok(())
        })
        .expect("failed to set sink for l2cap connection");

    // Set l2cap callback for when the channel is closed.
    l2cap_channel
        .on_close(move |_py| {
            println!("{}", "*** L2CAP channel closed".red());
            block_on(l2cap_to_tcp_tx.send(BridgeData::CloseSignal))
                .expect("failed to channel close signal to tcp");
            Ok(())
        })
        .expect("failed to set on_close callback for l2cap channel");

    println!(
        "{}",
        format!("### Connecting to TCP {tcp_host}:{tcp_port}...").yellow()
    );

    let l2cap_channel = Arc::new(Mutex::new(Some(l2cap_channel)));
    let tcp_stream = match TcpStream::connect(format!("{tcp_host}:{tcp_port}")).await {
        Ok(stream) => {
            println!("{}", "### Connected".green());
            Some(stream)
        }
        Err(err) => {
            println!("{}", format!("!!! Connection failed: {err}").red());
            if let Some(mut channel) = l2cap_channel.lock().await.take() {
                // Bumble might enter an invalid state if disconnection request is received from
                // l2cap client before receiving a disconnection response from the same client,
                // blocking this async call from returning.
                // See: https://github.com/google/bumble/issues/257
                select! {
                    res = channel.disconnect() => {
                        let _ = res.map_err(|e| eprintln!("Failed to call disconnect on l2cap channel: {e}"));
                    },
                    _ = tokio::time::sleep(Duration::from_secs(1)) => eprintln!("Timed out while calling disconnect on l2cap channel."),
                }
            }
            None
        }
    };

    match tcp_stream {
        None => {
            while let Some(bridge_data) = l2cap_to_tcp_rx.recv().await {
                match bridge_data {
                    BridgeData::Data(sdu) => {
                        println!("{}", format!("<<< [L2CAP SDU]: {} bytes", sdu.len()).cyan());
                        println!("{}", "!!! TCP socket not open, dropping".red())
                    }
                    BridgeData::CloseSignal => break,
                }
            }
        }
        Some(tcp_stream) => {
            let (tcp_reader, tcp_writer) = tcp_stream.into_split();

            // Do tcp stuff when something happens on the l2cap channel.
            let handle_l2cap_data_future =
                proxy_l2cap_rx_to_tcp_tx(l2cap_to_tcp_rx, tcp_writer, l2cap_channel.clone());

            // Do l2cap stuff when something happens on tcp.
            let handle_tcp_data_future =
                proxy_tcp_rx_to_l2cap_tx(tcp_reader, l2cap_channel.clone(), false);

            let (handle_l2cap_result, handle_tcp_result) =
                join!(handle_l2cap_data_future, handle_tcp_data_future);

            if let Err(e) = handle_l2cap_result {
                println!("!!! Error: {e}");
            }

            if let Err(e) = handle_tcp_result {
                println!("!!! Error: {e}");
            }
        }
    };

    Python::with_gil(|_| {
        // Must hold GIL at least once while/after dropping for Python heap object to ensure
        // de-allocation.
        drop(l2cap_channel);
    });

    Ok(())
}
