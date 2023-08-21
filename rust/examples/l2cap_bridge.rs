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

use anyhow::anyhow;
use bumble::wrapper::{
    device::Device,
    l2cap::LeConnectionOrientedChannel,
    logging::{bumble_env_logging_level, py_logging_basic_config},
    transport::Transport,
};
use clap::Parser as _;
use owo_colors::OwoColorize;
use pyo3::{PyObject, PyResult, Python};
use std::{future::Future, path, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    sync::{mpsc::Receiver, Mutex},
};

#[pyo3_asyncio::tokio::main]
async fn main() -> PyResult<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    py_logging_basic_config(bumble_env_logging_level("WARNING"))?;

    let cli = Cli::parse();

    println!("<<< connecting to HCI...");
    let transport = Transport::open(cli.hci_transport).await?;
    println!("<<< connected");

    let mut device = Device::from_config_file_with_hci(
        &cli.device_config,
        transport.source()?,
        transport.sink()?,
    )?;

    device.power_on().await?;

    match cli.subcommand {
        Subcommand::Server { tcp_host, tcp_port } => {
            let args = server_bridge::Args {
                psm: cli.psm,
                max_credits: cli.l2cap_coc_max_credits,
                mtu: cli.l2cap_coc_mtu,
                mps: cli.l2cap_coc_mps,
                tcp_host,
                tcp_port,
            };

            server_bridge::start(&args, &mut device).await?
        }
        Subcommand::Client {
            bluetooth_address,
            tcp_host,
            tcp_port,
        } => {
            let args = client_bridge::Args {
                psm: cli.psm,
                max_credits: cli.l2cap_coc_max_credits,
                mtu: cli.l2cap_coc_mtu,
                mps: cli.l2cap_coc_mps,
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

/// L2CAP CoC server bridge: waits for a peer to connect an L2CAP CoC channel
/// on a specified PSM. When the connection is made, the bridge connects a TCP
/// socket to a remote host and bridges the data in both directions, with flow
/// control.
/// When the L2CAP CoC channel is closed, the bridge disconnects the TCP socket
/// and waits for a new L2CAP CoC channel to be connected.
/// When the TCP connection is closed by the TCP server, XXXX
mod server_bridge {
    use crate::{
        proxy_l2cap_rx_to_tcp_tx, proxy_tcp_rx_to_l2cap_tx, run_future_with_current_task_locals,
        BridgeData,
    };
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
        pub max_credits: u16,
        pub mtu: u16,
        pub mps: u16,
        pub tcp_host: String,
        pub tcp_port: u16,
    }

    pub async fn start(args: &Args, device: &mut Device) -> PyResult<()> {
        let host = args.tcp_host.clone();
        let port = args.tcp_port;
        device.register_l2cap_channel_server(
            args.psm,
            move |_py, l2cap_channel| {
                let channel_info = match l2cap_channel.debug_string() {
                    Ok(info_string) => info_string,
                    Err(py_err) => format!("failed to get l2cap channel info ({})", py_err),
                };
                println!("{} {channel_info}", "*** L2CAP channel:".cyan());

                let host = host.clone();
                // Ensure Python event loop is available to l2cap `disconnect`
                let _ = run_future_with_current_task_locals(handle_connection_oriented_channel(
                    l2cap_channel,
                    host,
                    port,
                ));
                Ok(())
            },
            Some(args.max_credits),
            Some(args.mtu),
            Some(args.mps),
        )?;

        println!(
            "{}",
            format!("### Listening for CoC connection on PSM {}", args.psm).yellow()
        );

        device.on_connection(|_py, mut connection| {
            let connection_info = match connection.debug_string() {
                Ok(info_string) => info_string,
                Err(py_err) => format!("failed to get connection info ({})", py_err),
            };
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

    async fn handle_connection_oriented_channel(
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
                if let Some(channel) = l2cap_channel.lock().await.take() {
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
}

/// L2CAP CoC client bridge: connects to a BLE device, then waits for an inbound
/// TCP connection on a specified port number. When a TCP client connects, an
/// L2CAP CoC channel connection to the BLE device is established, and the data
/// is bridged in both directions, with flow control.
/// When the TCP connection is closed by the client, the L2CAP CoC channel is
/// disconnected, but the connection to the BLE device remains, ready for a new
/// TCP client to connect.
/// When the L2CAP CoC channel is closed, XXXX
mod client_bridge {
    use crate::{
        proxy_l2cap_rx_to_tcp_tx, proxy_tcp_rx_to_l2cap_tx, run_future_with_current_task_locals,
        BridgeData,
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
        pub max_credits: u16,
        pub mtu: u16,
        pub mps: u16,
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
        let ble_connection = Arc::new(ble_connection);
        // Ensure Python event loop is available to l2cap `disconnect`
        let _ = run_future_with_current_task_locals(async move {
            while let Ok((tcp_stream, addr)) = listener.accept().await {
                let ble_connection = ble_connection.clone();
                let _ = run_future_with_current_task_locals(handle_tcp_connection(
                    ble_connection,
                    tcp_stream,
                    addr,
                    psm,
                    max_credits,
                    mtu,
                    mps,
                ));
            }
            Ok(())
        });
        Ok(())
    }

    async fn handle_tcp_connection(
        ble_connection: Arc<Connection>,
        tcp_stream: TcpStream,
        addr: SocketAddr,
        psm: u16,
        max_credits: u16,
        mtu: u16,
        mps: u16,
    ) -> PyResult<()> {
        println!("{}", format!("<<< TCP connection from {}", addr).magenta());
        println!(
            "{}",
            format!(">>> Opening L2CAP channel on PSM = {}", psm).yellow()
        );

        let mut l2cap_channel = match ble_connection
            .open_l2cap_channel(psm, Some(max_credits), Some(mtu), Some(mps))
            .await
        {
            Ok(channel) => channel,
            Err(e) => {
                println!("{}", format!("!!! Connection failed: {e}").red());
                // TCP stream will get dropped after returning, automatically shutting it down.
                return Err(e);
            }
        };
        let channel_info = match l2cap_channel.debug_string() {
            Ok(info_string) => info_string,
            Err(py_err) => format!("failed to get l2cap channel info ({})", py_err),
        };

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
        let handle_tcp_data_future =
            proxy_tcp_rx_to_l2cap_tx(tcp_reader, l2cap_channel.clone(), true);

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
                    println!("{}", "!!! End of stream".yellow());

                    if let Some(channel) = l2cap_channel.lock().await.take() {
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
                if let Some(channel) = l2cap_channel.lock().await.take() {
                    let _ = channel.disconnect().await.map_err(|e| {
                        eprintln!("Failed to call disconnect on l2cap channel: {e}");
                    });
                }
                return Err(e.into());
            }
        }
    }
}

/// Copies the current thread's task locals into a Python "awaitable" and encapsulates it in a Rust
/// future, running it as a Python Task.
///
/// If the calling thread has a Python event loop, then the Python Task will too.
pub fn run_future_with_current_task_locals<F>(
    fut: F,
) -> PyResult<impl Future<Output = PyResult<PyObject>> + Send>
where
    F: Future<Output = PyResult<()>> + Send + 'static,
{
    Python::with_gil(|py| {
        let locals = pyo3_asyncio::tokio::get_current_locals(py)?;
        let future = pyo3_asyncio::tokio::scope(locals.clone(), fut);
        pyo3_asyncio::tokio::future_into_py_with_locals(py, locals.clone(), future)
            .and_then(pyo3_asyncio::tokio::into_future)
    })
}

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    pub(crate) subcommand: Subcommand,

    /// Device configuration file.
    ///
    /// See, for instance, `examples/device1.json` in the Python project.
    #[arg(long)]
    device_config: path::PathBuf,
    /// Bumble transport spec.
    ///
    /// <https://google.github.io/bumble/transports/index.html>
    #[arg(long)]
    hci_transport: String,

    /// PSM for L2CAP Connection-oriented Channel.
    ///
    /// Must be in the range [0, 65535].
    #[arg(long, default_value_t = 1234)]
    psm: u16,

    /// Maximum L2CAP CoC Credits.
    ///
    /// Must be in the range [1, 65535].
    #[arg(long, default_value_t = 128, value_parser = clap::value_parser!(u16).range(1..))]
    l2cap_coc_max_credits: u16,

    /// L2CAP CoC MTU
    ///
    /// Must be in the range [23, 65535].
    #[arg(long, default_value_t = 1022, value_parser = clap::value_parser!(u16).range(23..))]
    l2cap_coc_mtu: u16,

    /// L2CAP CoC MPS
    ///
    /// Must be in the range [23, 65535].
    #[arg(long, default_value_t = 1024, value_parser = clap::value_parser!(u16).range(23..))]
    l2cap_coc_mps: u16,
}

#[derive(clap::Subcommand)]
enum Subcommand {
    /// Starts an L2CAP server
    Server {
        /// TCP host that the l2cap server will connect to.
        /// Data is bridged like so:
        ///     TCP server <-> (TCP client / **L2CAP server**) <-> (L2CAP client / TCP server) <-> TCP client
        #[arg(long, default_value = "localhost")]
        tcp_host: String,
        /// TCP port that the server will connect to.
        ///
        /// Must be in the range [1, 65535].
        #[arg(long, default_value_t = 9544)]
        tcp_port: u16,
    },
    /// Starts an L2CAP client
    Client {
        /// L2cap server address that this l2cap client will connect to.
        bluetooth_address: String,
        /// TCP host that the l2cap client will bind to and listen for incoming TCP connections.
        /// Data is bridged like so:
        ///     TCP client <-> (TCP server / **L2CAP client**) <-> (L2CAP server / TCP client) <-> TCP Client
        #[arg(long, default_value = "localhost")]
        tcp_host: String,
        /// TCP port that the client will connect to.
        ///
        /// Must be in the range [1, 65535].
        #[arg(long, default_value_t = 9543)]
        tcp_port: u16,
    },
}
