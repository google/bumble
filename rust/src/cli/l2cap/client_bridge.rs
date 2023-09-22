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

/// L2CAP CoC client bridge: connects to a BLE device, then waits for an inbound
/// TCP connection on a specified port number. When a TCP client connects, an
/// L2CAP CoC channel connection to the BLE device is established, and the data
/// is bridged in both directions, with flow control.
/// When the TCP connection is closed by the client, the L2CAP CoC channel is
/// disconnected, but the connection to the BLE device remains, ready for a new
/// TCP client to connect.
/// When the L2CAP CoC channel is closed, the TCP connection is closed as well.
use crate::cli::l2cap::{
    inject_py_event_loop, proxy_l2cap_rx_to_tcp_tx, proxy_tcp_rx_to_l2cap_tx, BridgeData,
};
use bumble::wrapper::{
    device::{Connection, Device},
    hci::HciConstant,
};
use futures::executor::block_on;
use owo_colors::OwoColorize;
use pyo3::{PyResult, Python};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    join,
    net::{TcpListener, TcpStream},
    sync::{mpsc, Mutex},
};

pub struct Args {
    pub psm: u16,
    pub max_credits: Option<u16>,
    pub mtu: Option<u16>,
    pub mps: Option<u16>,
    pub bluetooth_address: String,
    pub tcp_host: String,
    pub tcp_port: u16,
}

pub async fn start(args: &Args, device: &mut Device) -> PyResult<()> {
    println!(
        "{}",
        format!("### Connecting to {}...", args.bluetooth_address).yellow()
    );
    let mut ble_connection = device.connect(&args.bluetooth_address).await?;
    ble_connection.on_disconnection(|_py, reason| {
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

    // Start the TCP server.
    let listener = TcpListener::bind(format!("{}:{}", args.tcp_host, args.tcp_port))
        .await
        .expect("failed to bind tcp to address");
    println!(
        "{}",
        format!(
            "### Listening for TCP connections on port {}",
            args.tcp_port
        )
        .magenta()
    );

    let psm = args.psm;
    let max_credits = args.max_credits;
    let mtu = args.mtu;
    let mps = args.mps;
    let ble_connection = Arc::new(Mutex::new(ble_connection));
    // spawn thread to handle incoming tcp connections
    tokio::spawn(inject_py_event_loop(async move {
        while let Ok((tcp_stream, addr)) = listener.accept().await {
            let ble_connection = ble_connection.clone();
            // spawn thread to handle this specific tcp connection
            if let Ok(future) = inject_py_event_loop(proxy_data_between_tcp_and_l2cap(
                ble_connection,
                tcp_stream,
                addr,
                psm,
                max_credits,
                mtu,
                mps,
            )) {
                tokio::spawn(future);
            }
        }
    })?);
    Ok(())
}

async fn proxy_data_between_tcp_and_l2cap(
    ble_connection: Arc<Mutex<Connection>>,
    tcp_stream: TcpStream,
    addr: SocketAddr,
    psm: u16,
    max_credits: Option<u16>,
    mtu: Option<u16>,
    mps: Option<u16>,
) -> PyResult<()> {
    println!("{}", format!("<<< TCP connection from {}", addr).magenta());
    println!(
        "{}",
        format!(">>> Opening L2CAP channel on PSM = {}", psm).yellow()
    );

    let mut l2cap_channel = match ble_connection
        .lock()
        .await
        .open_l2cap_channel(psm, max_credits, mtu, mps)
        .await
    {
        Ok(channel) => channel,
        Err(e) => {
            println!("{}", format!("!!! Connection failed: {e}").red());
            // TCP stream will get dropped after returning, automatically shutting it down.
            return Err(e);
        }
    };
    let channel_info = l2cap_channel
        .debug_string()
        .unwrap_or_else(|e| format!("failed to get l2cap channel info ({e})"));

    println!("{}{}", "*** L2CAP channel: ".cyan(), channel_info);

    let (l2cap_to_tcp_tx, l2cap_to_tcp_rx) = mpsc::channel::<BridgeData>(10);

    // Set l2cap callback (`set_sink`) for when data is received.
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

    let l2cap_channel = Arc::new(Mutex::new(Some(l2cap_channel)));
    let (tcp_reader, tcp_writer) = tcp_stream.into_split();

    // Do tcp stuff when something happens on the l2cap channel.
    let handle_l2cap_data_future =
        proxy_l2cap_rx_to_tcp_tx(l2cap_to_tcp_rx, tcp_writer, l2cap_channel.clone());

    // Do l2cap stuff when something happens on tcp.
    let handle_tcp_data_future = proxy_tcp_rx_to_l2cap_tx(tcp_reader, l2cap_channel.clone(), true);

    let (handle_l2cap_result, handle_tcp_result) =
        join!(handle_l2cap_data_future, handle_tcp_data_future);

    if let Err(e) = handle_l2cap_result {
        println!("!!! Error: {e}");
    }

    if let Err(e) = handle_tcp_result {
        println!("!!! Error: {e}");
    }

    Python::with_gil(|_| {
        // Must hold GIL at least once while/after dropping for Python heap object to ensure
        // de-allocation.
        drop(l2cap_channel);
    });

    Ok(())
}
