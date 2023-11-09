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

use bumble::wrapper::transport::Transport;
use nix::sys::stat::Mode;
use pyo3::PyResult;

#[pyo3_asyncio::tokio::test]
async fn fifo_transport_can_open() -> PyResult<()> {
    let dir = tempfile::tempdir().unwrap();
    let mut fifo = dir.path().to_path_buf();
    fifo.push("bumble-transport-fifo");
    nix::unistd::mkfifo(&fifo, Mode::S_IRWXU).unwrap();

    let mut t = Transport::open(format!("file:{}", fifo.to_str().unwrap())).await?;

    t.close().await?;

    Ok(())
}
