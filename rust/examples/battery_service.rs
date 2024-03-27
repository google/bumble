// Copyright 2024 Google LLC
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

//! Counterpart to the Python examples `battery_client` and `battery_server.py`.
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
//!     client \
//!     --target-addr F0:F1:F2:F3:F4:F5
//! ```

use anyhow::anyhow;
use async_trait::async_trait;
use bumble::wrapper::{
    assigned_numbers::services,
    att::{AttributePermission, AttributeRead, NoOpWrite},
    core::{AdvertisementDataBuilder, CommonDataType, Uuid16},
    device::{Connection, Device, Peer},
    gatt::{
        profile::proxy::BatteryServiceProxy,
        server::{Characteristic, CharacteristicValueHandler, Service},
        CharacteristicProperty,
    },
    hci::{packets::AddressType, Address},
    transport::Transport,
};
use clap::Parser as _;
use log::info;
use owo_colors::OwoColorize;
use pyo3::prelude::*;
use rand::Rng;
use std::time::Duration;

#[pyo3_asyncio::tokio::main]
async fn main() -> PyResult<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    let cli = Cli::parse();

    let transport = Transport::open(cli.transport).await?;
    let address = Address::from_be_hex("F0:F1:F2:F3:F4:F5", AddressType::RandomDeviceAddress)
        .map_err(|e| anyhow!(e))?;
    let device =
        Device::with_hci("Bumble", address, transport.source()?, transport.sink()?).await?;
    device.power_on().await?;

    match cli.subcommand {
        Subcommand::Client { target_addr } => {
            let target = Address::from_be_hex(&target_addr, AddressType::RandomDeviceAddress)
                .map_err(|e| anyhow!("{:?}", e))?;
            run_client(device, target).await
        }
        Subcommand::Server => run_server(device).await,
    }?;

    // wait until user kills the process
    tokio::signal::ctrl_c().await?;
    Ok(())
}

async fn run_client(device: Device, target_addr: Address) -> anyhow::Result<()> {
    info!("Connecting");
    let conn = device.connect(&target_addr).await?;
    let mut peer = Peer::new(conn).await?;
    info!("Discovering");
    peer.discover_services().await?;
    peer.discover_characteristics().await?;

    let battery_service = peer
        .create_service_proxy::<BatteryServiceProxy>()?
        .ok_or(anyhow::anyhow!("No battery service found"))?;

    info!("Getting characteristic");
    let mut battery_level_char = battery_service
        .battery_level()?
        .ok_or(anyhow::anyhow!("No battery level characteristic"))?;
    info!("Reading");
    info!(
        "{} {}",
        "Initial Battery Level:".green(),
        battery_level_char.read_value().await?
    );
    info!("Subscribing");
    battery_level_char
        .subscribe(|value| {
            info!("{} {:?}", "Battery level update:".green(), value);
        })
        .await?;

    Ok(())
}

async fn run_server(mut device: Device) -> anyhow::Result<()> {
    let uuid = services::BATTERY.uuid();
    let battery_level_uuid = Uuid16::from(0x2A19).into();
    let battery_level = Characteristic::new(
        battery_level_uuid,
        CharacteristicProperty::Read | CharacteristicProperty::Notify,
        AttributePermission::Readable.into(),
        CharacteristicValueHandler::new(Box::new(BatteryRead), Box::new(NoOpWrite)),
    );
    let service = Service::new(uuid.into(), vec![battery_level]);
    let service_handle = device.add_service(&service)?;

    let mut builder = AdvertisementDataBuilder::new();
    builder.append(CommonDataType::CompleteLocalName, "Bumble Battery")?;
    builder.append(
        CommonDataType::IncompleteListOf16BitServiceClassUuids,
        &uuid,
    )?;
    builder.append(
        CommonDataType::Appearance,
        // computer (0x02) - laptop (0x03)
        [0x02, 0x03].as_slice(),
    )?;
    device.set_advertising_data(builder)?;
    device.power_on().await?;
    device.start_advertising(true).await?;

    let char_handle = service_handle
        .characteristic_handle(battery_level_uuid)
        .expect("Battery level should be present");

    loop {
        tokio::time::sleep(Duration::from_secs(3)).await;
        device.notify_subscribers(char_handle).await?;
    }
}

struct BatteryRead;

#[async_trait]
impl AttributeRead for BatteryRead {
    async fn read(&self, conn: Connection) -> anyhow::Result<Vec<u8>> {
        info!("Client at {:?} reading battery level", conn.peer_address()?);
        Ok(vec![rand::thread_rng().gen_range(0..=100)])
    }
}

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Bumble transport spec.
    ///
    /// <https://google.github.io/bumble/transports/index.html>
    #[arg(long)]
    transport: String,

    #[clap(subcommand)]
    subcommand: Subcommand,
}

#[derive(clap::Subcommand, Debug, Clone)]
enum Subcommand {
    /// Battery service GATT client
    Client {
        /// Address to connect to
        #[arg(long)]
        target_addr: String,
    },
    /// Battery service GATT server
    Server,
}
