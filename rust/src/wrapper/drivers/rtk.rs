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

//! Drivers for Realtek controllers

use crate::wrapper::{host::Host, PyObjectExt};
use pyo3::{intern, types::PyModule, PyObject, PyResult, Python, ToPyObject};
use pyo3_asyncio::tokio::into_future;

pub use crate::internal::drivers::rtk::{Firmware, Patch};

/// Driver for a Realtek controller
pub struct Driver(PyObject);

impl Driver {
    /// Locate the driver for the provided host.
    pub async fn for_host(host: &Host, force: bool) -> PyResult<Option<Self>> {
        Python::with_gil(|py| {
            PyModule::import(py, intern!(py, "bumble.drivers.rtk"))?
                .getattr(intern!(py, "Driver"))?
                .call_method1(intern!(py, "for_host"), (&host.obj, force))
                .and_then(into_future)
        })?
        .await
        .map(|obj| obj.into_option(Self))
    }

    /// Check if the host has a known driver.
    pub async fn check(host: &Host) -> PyResult<bool> {
        Python::with_gil(|py| {
            PyModule::import(py, intern!(py, "bumble.drivers.rtk"))?
                .getattr(intern!(py, "Driver"))?
                .call_method1(intern!(py, "check"), (&host.obj,))
                .and_then(|obj| obj.extract::<bool>())
        })
    }

    /// Find the [DriverInfo] for the host, if one matches
    pub async fn driver_info_for_host(host: &Host) -> PyResult<Option<DriverInfo>> {
        Python::with_gil(|py| {
            PyModule::import(py, intern!(py, "bumble.drivers.rtk"))?
                .getattr(intern!(py, "Driver"))?
                .call_method1(intern!(py, "driver_info_for_host"), (&host.obj,))
                .and_then(into_future)
        })?
        .await
        .map(|obj| obj.into_option(DriverInfo))
    }

    /// Send a command to the device to drop firmware
    pub async fn drop_firmware(host: &mut Host) -> PyResult<()> {
        Python::with_gil(|py| {
            PyModule::import(py, intern!(py, "bumble.drivers.rtk"))?
                .getattr(intern!(py, "Driver"))?
                .call_method1(intern!(py, "drop_firmware"), (&host.obj,))
                .and_then(into_future)
        })?
        .await
        .map(|_| ())
    }

    /// Load firmware onto the device.
    pub async fn download_firmware(&mut self) -> PyResult<()> {
        Python::with_gil(|py| {
            self.0
                .call_method0(py, intern!(py, "download_firmware"))
                .and_then(|coroutine| into_future(coroutine.as_ref(py)))
        })?
        .await
        .map(|_| ())
    }
}

/// Metadata about a known driver & applicable device
pub struct DriverInfo(PyObject);

impl DriverInfo {
    /// Returns a list of all drivers that Bumble knows how to handle.
    pub fn all_drivers() -> PyResult<Vec<DriverInfo>> {
        Python::with_gil(|py| {
            PyModule::import(py, intern!(py, "bumble.drivers.rtk"))?
                .getattr(intern!(py, "Driver"))?
                .getattr(intern!(py, "DRIVER_INFOS"))?
                .iter()?
                .map(|r| r.map(|h| DriverInfo(h.to_object(py))))
                .collect::<PyResult<Vec<_>>>()
        })
    }

    /// The firmware file name to load from the filesystem, e.g. `foo_fw.bin`.
    pub fn firmware_name(&self) -> PyResult<String> {
        Python::with_gil(|py| {
            self.0
                .getattr(py, intern!(py, "fw_name"))?
                .as_ref(py)
                .extract::<String>()
        })
    }

    /// The config file name, if any, to load from the filesystem, e.g. `foo_config.bin`.
    pub fn config_name(&self) -> PyResult<Option<String>> {
        Python::with_gil(|py| {
            let obj = self.0.getattr(py, intern!(py, "config_name"))?;
            let handle = obj.as_ref(py);

            if handle.is_none() {
                Ok(None)
            } else {
                handle
                    .extract::<String>()
                    .map(|s| if s.is_empty() { None } else { Some(s) })
            }
        })
    }

    /// Whether or not config is required.
    pub fn config_needed(&self) -> PyResult<bool> {
        Python::with_gil(|py| {
            self.0
                .getattr(py, intern!(py, "config_needed"))?
                .as_ref(py)
                .extract::<bool>()
        })
    }

    /// ROM id
    pub fn rom(&self) -> PyResult<u32> {
        Python::with_gil(|py| self.0.getattr(py, intern!(py, "rom"))?.as_ref(py).extract())
    }
}
