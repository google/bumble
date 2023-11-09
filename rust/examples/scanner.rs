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

//! Counterpart to the Python example `run_scanner.py`.
//!
//! Device deduplication is done here rather than relying on the controller's filtering to provide
//! for additional features, like the ability to make deduplication time-bounded.

use bumble::{
    adv::CommonDataType,
    wrapper::{
        core::AdvertisementDataUnit,
        device::Device,
        hci::{packets::AddressType, Address},
        transport::Transport,
    },
};
use clap::Parser as _;
use itertools::Itertools;
use owo_colors::{OwoColorize, Style};
use pyo3::PyResult;
use std::{
    collections,
    sync::{Arc, Mutex},
    time,
};

#[pyo3_asyncio::tokio::main]
async fn main() -> PyResult<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    let cli = Cli::parse();

    let transport = Transport::open(cli.transport).await?;

    let address = Address::new("F0:F1:F2:F3:F4:F5", AddressType::RandomDeviceAddress)?;
    let mut device = Device::with_hci("Bumble", address, transport.source()?, transport.sink()?)?;

    // in practice, devices can send multiple advertisements from the same address, so we keep
    // track of a timestamp for each set of data
    let seen_advertisements = Arc::new(Mutex::new(collections::HashMap::<
        Vec<u8>,
        collections::HashMap<Vec<AdvertisementDataUnit>, time::Instant>,
    >::new()));

    let seen_adv_clone = seen_advertisements.clone();
    device.on_advertisement(move |_py, adv| {
        let rssi = adv.rssi()?;
        let data_units = adv.data()?.data_units()?;
        let addr = adv.address()?;

        let show_adv = if cli.filter_duplicates {
            let addr_bytes = addr.as_le_bytes()?;

            let mut seen_adv_cache = seen_adv_clone.lock().unwrap();
            let expiry_duration = time::Duration::from_secs(cli.dedup_expiry_secs);

            let advs_from_addr = seen_adv_cache.entry(addr_bytes).or_default();
            // we expect cache hits to be the norm, so we do a separate lookup to avoid cloning
            // on every lookup with entry()
            let show = if let Some(prev) = advs_from_addr.get_mut(&data_units) {
                let expired = prev.elapsed() > expiry_duration;
                *prev = time::Instant::now();
                expired
            } else {
                advs_from_addr.insert(data_units.clone(), time::Instant::now());
                true
            };

            // clean out anything we haven't seen in a while
            advs_from_addr.retain(|_, instant| instant.elapsed() <= expiry_duration);

            show
        } else {
            true
        };

        if !show_adv {
            return Ok(());
        }

        let addr_style = if adv.is_connectable()? {
            Style::new().yellow()
        } else {
            Style::new().red()
        };

        let (type_style, qualifier) = match adv.address()?.address_type()? {
            AddressType::PublicIdentityAddress | AddressType::PublicDeviceAddress => {
                (Style::new().cyan(), "")
            }
            _ => {
                if addr.is_static()? {
                    (Style::new().green(), "(static)")
                } else if addr.is_resolvable()? {
                    (Style::new().magenta(), "(resolvable)")
                } else {
                    (Style::new().default_color(), "")
                }
            }
        };

        println!(
            ">>> {} [{:?}] {qualifier}:\n  RSSI: {}",
            addr.as_hex()?.style(addr_style),
            addr.address_type()?.style(type_style),
            rssi,
        );

        data_units.into_iter().for_each(|(code, data)| {
            let matching = CommonDataType::for_type_code(code).collect::<Vec<_>>();
            let code_str = if matching.is_empty() {
                format!("0x{}", hex::encode_upper([code.into()]))
            } else {
                matching
                    .iter()
                    .map(|t| format!("{}", t))
                    .join(" / ")
                    .blue()
                    .to_string()
            };

            // use the first matching type's formatted data, if any
            let data_str = matching
                .iter()
                .filter_map(|t| {
                    t.format_data(&data).map(|formatted| {
                        format!(
                            "{} {}",
                            formatted,
                            format!("(raw: 0x{})", hex::encode_upper(&data)).dimmed()
                        )
                    })
                })
                .next()
                .unwrap_or_else(|| format!("0x{}", hex::encode_upper(&data)));

            println!("  [{}]: {}", code_str, data_str)
        });

        Ok(())
    })?;

    device.power_on().await?;
    // do our own dedup
    device.start_scanning(false).await?;

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

    /// Filter duplicate advertisements
    #[arg(long, default_value_t = false)]
    filter_duplicates: bool,

    /// How long before a deduplicated advertisement that hasn't been seen in a while is considered
    /// fresh again, in seconds
    #[arg(long, default_value_t = 10, requires = "filter_duplicates")]
    dedup_expiry_secs: u64,
}
