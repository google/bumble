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

use anyhow::anyhow;
use bumble::{
    adv::{AdvertisementDataBuilder, CommonDataType},
    wrapper::{
        device::Device,
        logging::{bumble_env_logging_level, py_logging_basic_config},
        transport::Transport,
    },
};
use clap::Parser as _;
use pyo3::PyResult;
use rand::Rng;
use std::path;

#[pyo3_asyncio::tokio::main]
async fn main() -> PyResult<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    let cli = Cli::parse();

    if cli.log_hci {
        py_logging_basic_config(bumble_env_logging_level("DEBUG"))?;
    }

    let transport = Transport::open(cli.transport).await?;

    let mut device = Device::from_config_file_with_hci(
        &cli.device_config,
        transport.source()?,
        transport.sink()?,
    )?;

    let mut adv_data = AdvertisementDataBuilder::new();

    adv_data
        .append(
            CommonDataType::CompleteLocalName,
            "Bumble from Rust".as_bytes(),
        )
        .map_err(|e| anyhow!(e))?;

    // Randomized TX power
    adv_data
        .append(
            CommonDataType::TxPowerLevel,
            &[rand::thread_rng().gen_range(-100_i8..=20) as u8],
        )
        .map_err(|e| anyhow!(e))?;

    device.power_on().await?;

    if cli.extended {
        println!("Starting extended advertisement...");
        device.start_advertising_extended(adv_data).await?;
    } else {
        device.set_advertising_data(adv_data)?;

        println!("Starting legacy advertisement...");
        device.start_advertising(true).await?;
    }

    // wait until user kills the process
    tokio::signal::ctrl_c().await?;

    if cli.extended {
        println!("Stopping extended advertisement...");
        device.stop_advertising_extended().await?;
    } else {
        println!("Stopping legacy advertisement...");
        device.stop_advertising().await?;
    }

    Ok(())
}

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Bumble device config.
    ///
    /// See, for instance, `examples/device1.json` in the Python project.
    #[arg(long)]
    device_config: path::PathBuf,

    /// Bumble transport spec.
    ///
    /// <https://google.github.io/bumble/transports/index.html>
    #[arg(long)]
    transport: String,

    /// Whether to perform an extended (BT 5.0) advertisement
    #[arg(long)]
    extended: bool,

    /// Log HCI commands
    #[arg(long)]
    log_hci: bool,
}
