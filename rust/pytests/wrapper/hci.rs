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
use bumble::wrapper::{
    controller::Controller,
    core::{TryFromPy, TryToPy},
    device::Device,
    hci::{
        packets::{
            AddressType, Enable, ErrorCode, LeScanType, LeScanningFilterPolicy,
            LeSetScanEnableBuilder, LeSetScanEnableComplete, LeSetScanParametersBuilder,
            LeSetScanParametersComplete, OwnAddressType,
        },
        Address, Error,
    },
    host::Host,
    link::Link,
};
use pyo3::{
    exceptions::PyException,
    Python, {PyErr, PyResult},
};

#[pyo3_asyncio::tokio::test]
async fn test_hci_roundtrip_success_and_failure() -> PyResult<()> {
    let address = Address::from_be_hex("F0:F1:F2:F3:F4:F5", AddressType::RandomDeviceAddress)
        .map_err(|e| anyhow!(e))?;
    let device = create_local_device(address).await?;

    device.power_on().await?;

    // BLE Spec Core v5.3
    // 7.8.9 LE Set Scan Parameters command
    // ...
    // The Host shall not issue this command when scanning is enabled in the
    // Controller; if it is the Command Disallowed error code shall be used.
    // ...

    let command = LeSetScanEnableBuilder {
        filter_duplicates: Enable::Disabled,
        // will cause failure later
        le_scan_enable: Enable::Enabled,
    };

    let event: LeSetScanEnableComplete = device
        .send_command(command.into(), false)
        .await?
        .try_into()
        .map_err(|e: Error| PyErr::new::<PyException, _>(e.to_string()))?;

    assert_eq!(ErrorCode::Success, event.get_status());

    let command = LeSetScanParametersBuilder {
        le_scan_type: LeScanType::Passive,
        le_scan_interval: 0,
        le_scan_window: 0,
        own_address_type: OwnAddressType::RandomDeviceAddress,
        scanning_filter_policy: LeScanningFilterPolicy::AcceptAll,
    };

    let event: LeSetScanParametersComplete = device
        .send_command(command.into(), false)
        .await?
        .try_into()
        .map_err(|e: Error| PyErr::new::<PyException, _>(e.to_string()))?;

    assert_eq!(ErrorCode::CommandDisallowed, event.get_status());

    Ok(())
}

#[pyo3_asyncio::tokio::test]
async fn address_roundtrip() -> PyResult<()> {
    for addr_type in [
        AddressType::PublicDeviceAddress,
        AddressType::RandomDeviceAddress,
        AddressType::PublicIdentityAddress,
        AddressType::RandomIdentityAddress,
    ] {
        let addr = Address::from_be_hex("F0:F1:F2:F3:F4:F5", addr_type).map_err(|e| anyhow!(e))?;

        Python::with_gil(|py| {
            assert_eq!(addr, Address::try_from_py(py, addr.try_to_py(py)?)?);

            Ok::<(), PyErr>(())
        })?;
    }

    Ok(())
}

async fn create_local_device(address: Address) -> PyResult<Device> {
    let link = Link::new_local_link()?;
    let controller = Controller::new("C1", None, None, Some(link), Some(address)).await?;
    let host = Host::new(controller.clone().into(), controller.into()).await?;
    Device::new(None, Some(address), None, Some(host), None).await
}
