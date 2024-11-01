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

//! GATT support

pub use crate::internal::gatt::{CharacteristicProperties, CharacteristicProperty};
use crate::wrapper::core::TryToPy;
use pyo3::{intern, prelude::PyModule, PyAny, PyResult, Python};

pub mod client;
pub mod profile;
pub mod server;

impl TryToPy for CharacteristicProperties {
    fn try_to_py<'py>(&self, py: Python<'py>) -> PyResult<&'py PyAny> {
        PyModule::import(py, intern!(py, "bumble.gatt"))?
            .getattr(intern!(py, "Characteristic"))?
            .getattr(intern!(py, "Properties"))?
            .call1((self.bits,))
    }
}
