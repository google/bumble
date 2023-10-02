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

//! Realtek firmware tools

use crate::{Download, Source};
use anyhow::anyhow;
use bumble::wrapper::{
    drivers::rtk::{Driver, DriverInfo, Firmware},
    host::{DriverFactory, Host},
    transport::Transport,
};
use owo_colors::{colors::css, OwoColorize};
use pyo3::PyResult;
use std::{fs, path};

pub(crate) async fn download(dl: Download) -> PyResult<()> {
    let data_dir = dl
        .output_dir
        .or_else(|| {
            directories::ProjectDirs::from("com", "google", "bumble")
                .map(|pd| pd.data_local_dir().join("firmware").join("realtek"))
        })
        .unwrap_or_else(|| {
            eprintln!("Could not determine standard data directory");
            path::PathBuf::from(".")
        });
    fs::create_dir_all(&data_dir)?;

    let (base_url, uses_bin_suffix) = match dl.source {
        Source::LinuxKernel => ("https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/plain/rtl_bt", true),
        Source::RealtekOpensource => ("https://github.com/Realtek-OpenSource/android_hardware_realtek/raw/rtk1395/bt/rtkbt/Firmware/BT", false),
        Source::LinuxFromScratch => ("https://anduin.linuxfromscratch.org/sources/linux-firmware/rtl_bt", true),
    };

    println!("Downloading");
    println!("{} {}", "FROM:".green(), base_url);
    println!("{} {}", "TO:".green(), data_dir.to_string_lossy());

    let url_for_file = |file_name: &str| {
        let url_suffix = if uses_bin_suffix {
            file_name
        } else {
            file_name.trim_end_matches(".bin")
        };

        let mut url = base_url.to_string();
        url.push('/');
        url.push_str(url_suffix);
        url
    };

    let to_download = if let Some(single) = dl.single {
        vec![(
            format!("{single}_fw.bin"),
            Some(format!("{single}_config.bin")),
            false,
        )]
    } else {
        DriverInfo::all_drivers()?
            .iter()
            .map(|di| Ok((di.firmware_name()?, di.config_name()?, di.config_needed()?)))
            .collect::<PyResult<Vec<_>>>()?
    };

    let client = SimpleClient::new();

    for (fw_filename, config_filename, config_needed) in to_download {
        println!("{}", "---".yellow());
        let fw_path = data_dir.join(&fw_filename);
        let config_path = config_filename.as_ref().map(|f| data_dir.join(f));

        if fw_path.exists() && !dl.overwrite {
            println!(
                "{}",
                format!("{} already exists, skipping", fw_path.to_string_lossy())
                    .fg::<css::Orange>()
            );
            continue;
        }
        if let Some(cp) = config_path.as_ref() {
            if cp.exists() && !dl.overwrite {
                println!(
                    "{}",
                    format!("{} already exists, skipping", cp.to_string_lossy())
                        .fg::<css::Orange>()
                );
                continue;
            }
        }

        let fw_contents = match client.get(&url_for_file(&fw_filename)).await {
            Ok(data) => {
                println!("Downloaded {}: {} bytes", fw_filename, data.len());
                data
            }
            Err(e) => {
                eprintln!(
                    "{} {} {:?}",
                    "Failed to download".red(),
                    fw_filename.red(),
                    e
                );
                continue;
            }
        };

        let config_contents = if let Some(cn) = &config_filename {
            match client.get(&url_for_file(cn)).await {
                Ok(data) => {
                    println!("Downloaded {}: {} bytes", cn, data.len());
                    Some(data)
                }
                Err(e) => {
                    if config_needed {
                        eprintln!("{} {} {:?}", "Failed to download".red(), cn.red(), e);
                        continue;
                    } else {
                        eprintln!(
                            "{}",
                            format!("No config available as {cn}").fg::<css::Orange>()
                        );
                        None
                    }
                }
            }
        } else {
            None
        };

        fs::write(&fw_path, &fw_contents)?;
        if !dl.no_parse && config_filename.is_some() {
            println!("{} {}", "Parsing:".cyan(), &fw_filename);
            match Firmware::parse(&fw_contents).map_err(|e| anyhow!("Parse error: {:?}", e)) {
                Ok(fw) => dump_firmware_desc(&fw),
                Err(e) => {
                    eprintln!(
                        "{} {:?}",
                        "Could not parse firmware:".fg::<css::Orange>(),
                        e
                    );
                }
            }
        }
        if let Some((cp, cd)) = config_path
            .as_ref()
            .and_then(|p| config_contents.map(|c| (p, c)))
        {
            fs::write(cp, &cd)?;
        }
    }

    Ok(())
}

pub(crate) fn parse(firmware_path: &path::Path) -> PyResult<()> {
    let contents = fs::read(firmware_path)?;
    let fw = Firmware::parse(&contents)
        // squish the error into a string to avoid the error type requiring that the input be
        // 'static
        .map_err(|e| anyhow!("Parse error: {:?}", e))?;

    dump_firmware_desc(&fw);

    Ok(())
}

pub(crate) async fn info(transport: &str, force: bool) -> PyResult<()> {
    let transport = Transport::open(transport).await?;

    let mut host = Host::new(transport.source()?, transport.sink()?).await?;
    host.reset(DriverFactory::None).await?;

    if !force && !Driver::check(&host).await? {
        println!("USB device not supported by this RTK driver");
    } else if let Some(driver_info) = Driver::driver_info_for_host(&host).await? {
        println!("Driver:");
        println!("  {:10} {:04X}", "ROM:", driver_info.rom()?);
        println!("  {:10} {}", "Firmware:", driver_info.firmware_name()?);
        println!(
            "  {:10} {}",
            "Config:",
            driver_info.config_name()?.unwrap_or_default()
        );
    } else {
        println!("Firmware already loaded or no supported driver for this device.")
    }

    Ok(())
}

pub(crate) async fn load(transport: &str, force: bool) -> PyResult<()> {
    let transport = Transport::open(transport).await?;

    let mut host = Host::new(transport.source()?, transport.sink()?).await?;
    host.reset(DriverFactory::None).await?;

    match Driver::for_host(&host, force).await? {
        None => {
            eprintln!("Firmware already loaded or no supported driver for this device.");
        }
        Some(mut d) => d.download_firmware().await?,
    };

    Ok(())
}

pub(crate) async fn drop(transport: &str) -> PyResult<()> {
    let transport = Transport::open(transport).await?;

    let mut host = Host::new(transport.source()?, transport.sink()?).await?;
    host.reset(DriverFactory::None).await?;

    Driver::drop_firmware(&mut host).await?;

    Ok(())
}

fn dump_firmware_desc(fw: &Firmware) {
    println!(
        "Firmware: version=0x{:08X} project_id=0x{:04X}",
        fw.version(),
        fw.project_id()
    );
    for p in fw.patches() {
        println!(
            "  Patch: chip_id=0x{:04X}, {} bytes, SVN Version={:08X}",
            p.chip_id(),
            p.contents().len(),
            p.svn_version()
        )
    }
}

struct SimpleClient {
    client: reqwest::Client,
}

impl SimpleClient {
    fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    async fn get(&self, url: &str) -> anyhow::Result<Vec<u8>> {
        let resp = self.client.get(url).send().await?;
        if !resp.status().is_success() {
            return Err(anyhow!("Bad status: {}", resp.status()));
        }
        let bytes = resp.bytes().await?;
        Ok(bytes.as_ref().to_vec())
    }
}
