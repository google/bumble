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

//! Rust version of the Python `l2cap_bridge.py` found under the `apps` folder.

use crate::L2cap;
use anyhow::anyhow;
use bumble::wrapper::{device::Device, l2cap::LeConnectionOrientedChannel, transport::Transport};
use owo_colors::{colors::css::Orange, OwoColorize};
use pyo3::{PyResult, Python};
use std::{future::Future, path::PathBuf, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    sync::{mpsc::Receiver, Mutex},
};

mod client_bridge;
mod server_bridge;

pub(crate) async fn run(
    command: L2cap,
    device_config: PathBuf,
    transport: String,
    psm: u16,
    max_credits: Option<u16>,
    mtu: Option<u16>,
    mps: Option<u16>,
) -> PyResult<()> {
    println!("<<< connecting to HCI...");
    let transport = Transport::open(transport).await?;
    println!("<<< connected");

    let mut device =
        Device::from_config_file_with_hci(&device_config, transport.source()?, transport.sink()?)?;

    device.power_on().await?;

    match command {
        L2cap::Server { tcp_host, tcp_port } => {
            let args = server_bridge::Args {
                psm,
                max_credits,
                mtu,
                mps,
                tcp_host,
                tcp_port,
            };

            server_bridge::start(&args, &mut device).await?
        }
        L2cap::Client {
            bluetooth_address,
            tcp_host,
            tcp_port,
        } => {
            let args = client_bridge::Args {
                psm,
                max_credits,
                mtu,
                mps,
                bluetooth_address,
                tcp_host,
                tcp_port,
            };

            client_bridge::start(&args, &mut device).await?
        }
    };

    // wait until user kills the process
    tokio::signal::ctrl_c().await?;

    Ok(())
}

/// Used for channeling data from Python callbacks to a Rust consumer.
enum BridgeData {
    Data(Vec<u8>),
    CloseSignal,
}

async fn proxy_l2cap_rx_to_tcp_tx(
    mut l2cap_data_receiver: Receiver<BridgeData>,
    mut tcp_writer: OwnedWriteHalf,
    l2cap_channel: Arc<Mutex<Option<LeConnectionOrientedChannel>>>,
) -> anyhow::Result<()> {
    while let Some(bridge_data) = l2cap_data_receiver.recv().await {
        match bridge_data {
            BridgeData::Data(sdu) => {
                println!("{}", format!("<<< [L2CAP SDU]: {} bytes", sdu.len()).cyan());
                tcp_writer
                    .write_all(sdu.as_ref())
                    .await
                    .map_err(|_| anyhow!("Failed to write to tcp stream"))?;
                tcp_writer
                    .flush()
                    .await
                    .map_err(|_| anyhow!("Failed to flush tcp stream"))?;
            }
            BridgeData::CloseSignal => {
                l2cap_channel.lock().await.take();
                tcp_writer
                    .shutdown()
                    .await
                    .map_err(|_| anyhow!("Failed to shut down write half of tcp stream"))?;
                return Ok(());
            }
        }
    }
    Ok(())
}

async fn proxy_tcp_rx_to_l2cap_tx(
    mut tcp_reader: OwnedReadHalf,
    l2cap_channel: Arc<Mutex<Option<LeConnectionOrientedChannel>>>,
    drain_l2cap_after_write: bool,
) -> PyResult<()> {
    let mut buf = [0; 4096];
    loop {
        match tcp_reader.read(&mut buf).await {
            Ok(len) => {
                if len == 0 {
                    println!("{}", "!!! End of stream".fg::<Orange>());

                    if let Some(mut channel) = l2cap_channel.lock().await.take() {
                        channel.disconnect().await.map_err(|e| {
                            eprintln!("Failed to call disconnect on l2cap channel: {e}");
                            e
                        })?;
                    }
                    return Ok(());
                }

                println!("{}", format!("<<< [TCP DATA]: {len} bytes").blue());
                match l2cap_channel.lock().await.as_mut() {
                    None => {
                        println!("{}", "!!! L2CAP channel not connected, dropping".red());
                        return Ok(());
                    }
                    Some(channel) => {
                        channel.write(&buf[..len])?;
                        if drain_l2cap_after_write {
                            channel.drain().await?;
                        }
                    }
                }
            }
            Err(e) => {
                println!("{}", format!("!!! TCP connection lost: {}", e).red());
                if let Some(mut channel) = l2cap_channel.lock().await.take() {
                    let _ = channel.disconnect().await.map_err(|e| {
                        eprintln!("Failed to call disconnect on l2cap channel: {e}");
                    });
                }
                return Err(e.into());
            }
        }
    }
}

/// Copies the current thread's Python even loop (contained in `TaskLocals`) into the given future.
/// Useful when sending work to another thread that calls Python code which calls `get_running_loop()`.
pub fn inject_py_event_loop<F, R>(fut: F) -> PyResult<impl Future<Output = R>>
where
    F: Future<Output = R> + Send + 'static,
{
    let locals = Python::with_gil(pyo3_asyncio::tokio::get_current_locals)?;
    Ok(pyo3_asyncio::tokio::scope(locals, fut))
}
