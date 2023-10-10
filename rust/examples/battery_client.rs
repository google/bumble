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

//! Counterpart to the Python example `battery_server.py`.
//!
//! Start an Android emulator from Android Studio, or otherwise have netsim running.
//!
//! Run the server from the project root:
//! ```
//! PYTHONPATH=. python examples/battery_server.py \
//!     examples/device1.json android-netsim
//! ```
//!
//! Then run this example from the `rust` directory:
//!
//! ```
//! PYTHONPATH=..:/path/to/virtualenv/site-packages/ \
//!     cargo run --example battery_client -- \
//!     --transport android-netsim \
//!     --target-addr F0:F1:F2:F3:F4:F5
//! ```

use bumble::wrapper::{
    device::{Device, Peer},
    hci::{packets::AddressType, Address},
    profile::BatteryServiceProxy,
    transport::Transport,
    PyObjectExt,
};
use clap::Parser as _;
use log::info;
use owo_colors::OwoColorize;
use pyo3::prelude::*;

#[pyo3_asyncio::tokio::main]
async fn main() -> PyResult<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    let cli = Cli::parse();

    let transport = Transport::open(cli.transport).await?;

    let address = Address::new("F0:F1:F2:F3:F4:F5", AddressType::RandomDeviceAddress)?;
    let device = Device::with_hci("Bumble", address, transport.source()?, transport.sink()?)?;

    device.power_on().await?;

    let conn = device.connect(&cli.target_addr).await?;
    let mut peer = Peer::new(conn)?;
    for mut s in peer.discover_services().await? {
        s.discover_characteristics().await?;
    }
    let battery_service = peer
        .create_service_proxy::<BatteryServiceProxy>()?
        .ok_or(anyhow::anyhow!("No battery service found"))?;

    let mut battery_level_char = battery_service
        .battery_level()?
        .ok_or(anyhow::anyhow!("No battery level characteristic"))?;
    info!(
        "{} {}",
        "Initial Battery Level:".green(),
        battery_level_char
            .read_value()
            .await?
            .extract_with_gil::<u32>()?
    );
    battery_level_char
        .subscribe(|_py, args| {
            info!(
                "{} {:?}",
                "Battery level update:".green(),
                args.get_item(0)?.extract::<u32>()?,
            );
            Ok(())
        })
        .await?;

    // wait until user kills the process
    tokio::signal::ctrl_c().await?;
    Ok(())
}

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Bumble transport spec.
    ///
    /// <https://google.github.io/bumble/transports/index.html>
    #[arg(long)]
    transport: String,

    /// Address to connect to
    #[arg(long)]
    target_addr: String,
}
