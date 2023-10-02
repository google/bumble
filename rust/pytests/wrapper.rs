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

use bumble::wrapper::{
    controller::Controller,
    device::Device,
    drivers::rtk::DriverInfo,
    hci::{
        packets::{
            AddressType, ErrorCode, ReadLocalVersionInformationBuilder,
            ReadLocalVersionInformationComplete,
        },
        Address, Error,
    },
    host::Host,
    link::Link,
    transport::Transport,
};
use nix::sys::stat::Mode;
use pyo3::{
    exceptions::PyException,
    {PyErr, PyResult},
};

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

#[pyo3_asyncio::tokio::test]
async fn realtek_driver_info_all_drivers() -> PyResult<()> {
    assert_eq!(12, DriverInfo::all_drivers()?.len());
    Ok(())
}

#[pyo3_asyncio::tokio::test]
async fn hci_command_wrapper_has_correct_methods() -> PyResult<()> {
    let address = Address::new("F0:F1:F2:F3:F4:F5", &AddressType::RandomDeviceAddress)?;
    let link = Link::new_local_link()?;
    let controller = Controller::new("C1", None, None, Some(link), Some(address.clone())).await?;
    let host = Host::new(controller.clone().into(), controller.into()).await?;
    let device = Device::new(None, Some(address), None, Some(host), None)?;

    device.power_on().await?;

    // Send some simple command. A successful response means [HciCommandWrapper] has the minimum
    // required interface for the Python code to think its an [HCI_Command] object.
    let command = ReadLocalVersionInformationBuilder {};
    let event: ReadLocalVersionInformationComplete = device
        .send_command(&command.into(), true)
        .await?
        .try_into()
        .map_err(|e: Error| PyErr::new::<PyException, _>(e.to_string()))?;

    assert_eq!(ErrorCode::Success, event.get_status());
    Ok(())
}
