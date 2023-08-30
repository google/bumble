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

//! CLI tools for Bumble

#![deny(missing_docs, unsafe_code)]

use bumble::wrapper::logging::{bumble_env_logging_level, py_logging_basic_config};
use clap::Parser as _;
use pyo3::PyResult;
use std::{fmt, path};

mod cli;

#[pyo3_asyncio::tokio::main]
async fn main() -> PyResult<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    py_logging_basic_config(bumble_env_logging_level("INFO"))?;

    let cli: Cli = Cli::parse();

    match cli.subcommand {
        Subcommand::Firmware { subcommand: fw } => match fw {
            Firmware::Realtek { subcommand: rtk } => match rtk {
                Realtek::Download(dl) => {
                    cli::firmware::rtk::download(dl).await?;
                }
                Realtek::Drop { transport } => cli::firmware::rtk::drop(&transport).await?,
                Realtek::Info { transport, force } => {
                    cli::firmware::rtk::info(&transport, force).await?;
                }
                Realtek::Load { transport, force } => {
                    cli::firmware::rtk::load(&transport, force).await?
                }
                Realtek::Parse { firmware_path } => cli::firmware::rtk::parse(&firmware_path)?,
            },
        },
        Subcommand::L2cap {
            subcommand,
            device_config,
            transport,
            psm,
            l2cap_coc_max_credits,
            l2cap_coc_mtu,
            l2cap_coc_mps,
        } => {
            cli::l2cap::run(
                subcommand,
                device_config,
                transport,
                psm,
                l2cap_coc_max_credits,
                l2cap_coc_mtu,
                l2cap_coc_mps,
            )
            .await?
        }
        Subcommand::Usb { subcommand } => match subcommand {
            Usb::Probe(probe) => cli::usb::probe(probe.verbose)?,
        },
    }

    Ok(())
}

#[derive(clap::Parser)]
struct Cli {
    #[clap(subcommand)]
    subcommand: Subcommand,
}

#[derive(clap::Subcommand, Debug, Clone)]
enum Subcommand {
    /// Manage device firmware
    Firmware {
        #[clap(subcommand)]
        subcommand: Firmware,
    },
    /// L2cap client/server operations
    L2cap {
        #[command(subcommand)]
        subcommand: L2cap,

        /// Device configuration file.
        ///
        /// See, for instance, `examples/device1.json` in the Python project.
        #[arg(long)]
        device_config: path::PathBuf,
        /// Bumble transport spec.
        ///
        /// <https://google.github.io/bumble/transports/index.html>
        #[arg(long)]
        transport: String,

        /// PSM for L2CAP Connection-oriented Channel.
        ///
        /// Must be in the range [0, 65535].
        #[arg(long)]
        psm: u16,

        /// Maximum L2CAP CoC Credits. When not specified, lets Bumble set the default.
        ///
        /// Must be in the range [1, 65535].
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
        l2cap_coc_max_credits: Option<u16>,

        /// L2CAP CoC MTU. When not specified, lets Bumble set the default.
        ///
        /// Must be in the range [23, 65535].
        #[arg(long, value_parser = clap::value_parser!(u16).range(23..))]
        l2cap_coc_mtu: Option<u16>,

        /// L2CAP CoC MPS. When not specified, lets Bumble set the default.
        ///
        /// Must be in the range [23, 65535].
        #[arg(long, value_parser = clap::value_parser!(u16).range(23..))]
        l2cap_coc_mps: Option<u16>,
    },
    /// USB operations
    Usb {
        #[clap(subcommand)]
        subcommand: Usb,
    },
}

#[derive(clap::Subcommand, Debug, Clone)]
enum Firmware {
    /// Manage Realtek chipset firmware
    Realtek {
        #[clap(subcommand)]
        subcommand: Realtek,
    },
}

#[derive(clap::Subcommand, Debug, Clone)]

enum Realtek {
    /// Download Realtek firmware
    Download(Download),
    /// Drop firmware from a USB device
    Drop {
        /// Bumble transport spec. Must be for a USB device.
        ///
        /// <https://google.github.io/bumble/transports/index.html>
        #[arg(long)]
        transport: String,
    },
    /// Show driver info for a USB device
    Info {
        /// Bumble transport spec. Must be for a USB device.
        ///
        /// <https://google.github.io/bumble/transports/index.html>
        #[arg(long)]
        transport: String,
        /// Try to resolve driver info even if USB info is not available, or if the USB
        /// (vendor,product) tuple is not in the list of known compatible RTK USB dongles.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Load firmware onto a USB device
    Load {
        /// Bumble transport spec. Must be for a USB device.
        ///
        /// <https://google.github.io/bumble/transports/index.html>
        #[arg(long)]
        transport: String,
        /// Load firmware even if the USB info doesn't match.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Parse a firmware file
    Parse {
        /// Firmware file to parse
        firmware_path: path::PathBuf,
    },
}

#[derive(clap::Args, Debug, Clone)]
struct Download {
    /// Directory to download to. Defaults to an OS-specific path specific to the Bumble tool.
    #[arg(long)]
    output_dir: Option<path::PathBuf>,
    /// Source to download from
    #[arg(long, default_value_t = Source::LinuxKernel)]
    source: Source,
    /// Only download a single image
    #[arg(long, value_name = "base name")]
    single: Option<String>,
    /// Overwrite existing files
    #[arg(long, default_value_t = false)]
    overwrite: bool,
    /// Don't print the parse results for the downloaded file names
    #[arg(long)]
    no_parse: bool,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum Source {
    LinuxKernel,
    RealtekOpensource,
    LinuxFromScratch,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Source::LinuxKernel => write!(f, "linux-kernel"),
            Source::RealtekOpensource => write!(f, "realtek-opensource"),
            Source::LinuxFromScratch => write!(f, "linux-from-scratch"),
        }
    }
}

#[derive(clap::Subcommand, Debug, Clone)]
enum L2cap {
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
        ///     TCP client <-> (TCP server / **L2CAP client**) <-> (L2CAP server / TCP client) <-> TCP server
        #[arg(long, default_value = "localhost")]
        tcp_host: String,
        /// TCP port that the client will connect to.
        ///
        /// Must be in the range [1, 65535].
        #[arg(long, default_value_t = 9543)]
        tcp_port: u16,
    },
}

#[derive(clap::Subcommand, Debug, Clone)]
enum Usb {
    /// Probe the USB bus for Bluetooth devices
    Probe(Probe),
}

#[derive(clap::Args, Debug, Clone)]
struct Probe {
    /// Show additional info for each USB device
    #[arg(long, default_value_t = false)]
    verbose: bool,
}
