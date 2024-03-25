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

use anyhow::anyhow;
use cfg_if::cfg_if;
use log::{debug, info, warn};
use rand::Rng;
use std::{env, fs, future::Future, io::Read as _, path};
use tokio::{
    io::{self, AsyncBufReadExt as _},
    select,
    sync::mpsc,
    task,
};
use tokio_util::sync::CancellationToken;

/// Run the provided closure with rootcanal running in the background.
///
/// Port info for the rootcanal instance is passed to the closure; those ports must be used rather
/// than the default rootcanal ports so that multiple tests may run concurrently without clashing.
///
/// Sets up `env_logger`, if it wasn't already configured, so that debug logging with rootcanal
/// output can be enabled with `RUST_LOG=debug` env var.
///
/// If the correct rootcanal binary isn't already cached, it will be downloaded from GitHub
/// Releases if a binary is available for the current OS & architecture.
///
/// This is a stop-gap until rootcanal's build is improved to the point that a rootcanal-sys crate,
/// and using rootcanal as a library rather than a separate process, becomes feasible.
pub(crate) async fn run_with_rootcanal<O, F>(closure: F) -> anyhow::Result<()>
where
    O: Future<Output = anyhow::Result<()>>,
    F: Fn(RootcanalPorts) -> O,
{
    env_logger::try_init().unwrap_or_else(|_e| debug!("logger already initialized; skipping"));

    let bin = find_rootcanal().await?;

    // loop until available ports are found
    loop {
        // random non-privileged ports
        let hci_port: u16 = rand::thread_rng().gen_range(1_025..65_535);
        let rc_ports = RootcanalPorts {
            hci_port,
            link_ble_port: hci_port + 1,
            link_port: hci_port + 2,
            test_port: hci_port + 3,
        };

        debug!("Trying to launch rootcanal with {:?}", rc_ports);

        let mut child = tokio::process::Command::new(bin.as_os_str())
            .args([
                "-hci_port",
                &rc_ports.hci_port.to_string(),
                "-link_ble_port",
                &rc_ports.link_ble_port.to_string(),
                "-link_port",
                &rc_ports.link_port.to_string(),
                "-test_port",
                &rc_ports.test_port.to_string(),
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .stdin(std::process::Stdio::null())
            // clean up the process if the test panics (e.g. assert failure)
            .kill_on_drop(true)
            .spawn()?;

        let (tx, mut rx) = mpsc::unbounded_channel();
        let stdout_task = spawn_output_copier(child.stdout.take().unwrap(), tx.clone());
        let stderr_task = spawn_output_copier(child.stderr.take().unwrap(), tx);

        // Rootcanal doesn't exit or write to stderr if it can't bind to ports, so we
        // search through stdout to look for `Error binding...` that would show up before
        // `initialize: Finished`.

        let started_successfully = loop {
            match rx.recv().await {
                None => {
                    warn!("Rootcanal output copiers aborted early");
                    break false;
                }
                Some(line) => {
                    if line.contains("Error binding test channel listener socket to port") {
                        debug!("Rootcanal failed to bind ports {:?}: {line}", rc_ports);
                        break false;
                    }

                    if line.contains("initialize: Finished") {
                        // Didn't see an error, so rootcanal is usable
                        break true;
                    }
                }
            }
        };

        // Print further rootcanal output as it arrives so that it will interleave with
        // test printlns, etc
        let cancellation_token = CancellationToken::new();
        let printer_task = spawn_printer(rx, cancellation_token.clone());

        let test_res = if started_successfully {
            // run test task
            Some(closure(rc_ports).await)
        } else {
            None
        };

        child
            .start_kill()
            .unwrap_or_else(|e| warn!("Could not kill rootcanal: {:?}", e));
        cancellation_token.cancel();
        stdout_task
            .await
            .unwrap_or_else(|e| warn!("stdout task failed: {:?}", e));
        stderr_task
            .await
            .unwrap_or_else(|e| warn!("stderr task failed: {:?}", e));
        printer_task
            .await
            .unwrap_or_else(|e| warn!("print task failed: {:?}", e));

        match child.wait().await {
            Ok(exit) => debug!("exit status: {exit}"),
            Err(e) => warn!("Error while waiting for child: {:?}", e),
        }

        if let Some(res) = test_res {
            break res;
        }
    }
}

#[derive(Debug)]
pub(crate) struct RootcanalPorts {
    /// HCI TCP server port
    pub(crate) hci_port: u16,
    /// LE link TCP server port
    pub(crate) link_ble_port: u16,
    /// Link TCP server port
    pub(crate) link_port: u16,
    /// Test TCP port
    pub(crate) test_port: u16,
}

/// Spawn a task that reads lines from `read` and writes them to `tx`
fn spawn_output_copier<R: io::AsyncRead + Send + Unpin + 'static>(
    read: R,
    tx: mpsc::UnboundedSender<String>,
) -> task::JoinHandle<()> {
    tokio::spawn(async move {
        let reader = io::BufReader::new(read);
        let mut lines = reader.lines();

        loop {
            let res = lines.next_line().await;
            match res {
                Ok(None) => {
                    // no more lines
                    return;
                }
                Ok(Some(l)) => {
                    if tx.send(l).is_err() {
                        // rx closed
                        return;
                    };
                }
                Err(e) => {
                    warn!("Could not read rootcanal output: {:?}", e)
                }
            }
        }
    })
}

/// Spawn a task to print output from rootcanal as it happens
fn spawn_printer(
    mut rx: mpsc::UnboundedReceiver<String>,
    cancellation_token: CancellationToken,
) -> task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            select! {
                _ = cancellation_token.cancelled() => {
                    // signal copier tasks to close
                    rx.close();
                    // print any buffered lines
                    while let Some(line) = rx.recv().await {
                        debug!("{line}")
                    }

                    break;
                }
                opt = rx.recv() => {
                    match opt {
                        None => break,
                        Some(line) => debug!("{line}"),
                    }
                }
            }
        }
    })
}

/// Returns the path to a rootcanal binary, downloading it from GitHub if necessary.
async fn find_rootcanal() -> anyhow::Result<path::PathBuf> {
    let version = "1.10.0";
    // from https://github.com/google/rootcanal/releases
    let (url, zip_bin_path) = match (env::consts::OS, env::consts::ARCH) {
        ("linux", "x86_64") => ("https://github.com/google/rootcanal/releases/download/v1.10.0/rootcanal-1.10.0-linux-x86_64.zip", "rootcanal-linux-x86_64/bin/rootcanal"),
        ("macos", "x86_64")  => ("https://github.com/google/rootcanal/releases/download/v1.10.0/rootcanal-1.10.0-macos-x86_64.zip", "rootcanal-macos-x86_64/bin/rootcanal"),
        _ => {
            return Err(anyhow!("No Rootcanal binary available for {} {}, sorry", env::consts::OS, env::consts::ARCH));
        }
    };
    let rootcanal_dir = directories::ProjectDirs::from("com", "google", "bumble")
        .map(|pd| {
            pd.data_local_dir()
                .join("test-tools")
                .join("rootcanal")
                .join(version)
                .join("bin")
        })
        .ok_or_else(|| anyhow!("Couldn't resolve rootcanal dir"))?;
    fs::create_dir_all(&rootcanal_dir)?;

    with_dir_lock(&rootcanal_dir.join(".lockdir"), async {
        let rootcanal_bin = rootcanal_dir.join("rootcanal");
        if rootcanal_bin.exists() {
            return Ok(rootcanal_bin);
        }

        info!("Downloading rootcanal {version} to {:?}", rootcanal_bin);

        let resp_body = reqwest::get(url).await?.bytes().await?;
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&resp_body))?;
        let mut zip_entry = archive.by_name(zip_bin_path)?;
        let mut buf = Vec::new();
        zip_entry.read_to_end(&mut buf)?;
        fs::write(&rootcanal_bin, buf)?;

        cfg_if! {
            if #[cfg(unix)] {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&rootcanal_bin, fs::Permissions::from_mode(0o744))?;
            }
        }

        Ok(rootcanal_bin)
    })
    .await
}

/// Execute `closure` with a simple directory lock held.
///
/// Assumes that directory creation is atomic, which it is on most OS's.
async fn with_dir_lock<T>(
    dir: &path::Path,
    closure: impl Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    // wait until we can create the dir
    loop {
        match fs::create_dir(dir) {
            Ok(_) => break,
            Err(e) => {
                if e.kind() == io::ErrorKind::AlreadyExists {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                } else {
                    warn!(
                        "Unexpected error creating lockdir at {}: {:?}",
                        dir.to_string_lossy(),
                        e
                    );
                    return Err(e.into());
                }
            }
        }
    }
    let res = closure.await;

    let _ = fs::remove_dir(dir).map_err(|e| warn!("Could not remove lockdir: {:?}", e));
    res
}
