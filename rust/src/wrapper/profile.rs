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

//! GATT profiles

use crate::wrapper::{gatt::Characteristic, gatt_client::ProfileServiceProxy};
use pyo3::{intern, PyObject, PyResult, Python};

/// Exposes the battery GATT service
pub struct BatteryService(PyObject);

impl BatteryService {
    /// Get the battery level, if available
    pub fn battery_level(&self) -> PyResult<Option<Characteristic>> {
        Python::with_gil(|py| {
            self.0
                .getattr(py, intern!(py, "battery_level"))
                .map(|level| {
                    if level.is_none(py) {
                        None
                    } else {
                        Some(Characteristic(level))
                    }
                })
        })
    }
}

impl ProfileServiceProxy for BatteryService {
    const PROXY_CLASS_MODULE: &'static str = "bumble.profiles.battery_service";
    const PROXY_CLASS_NAME: &'static str = "BatteryServiceProxy";

    fn wrap(obj: PyObject) -> Self {
        Self(obj)
    }
}