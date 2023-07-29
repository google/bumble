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

//! HCI

use itertools::Itertools as _;
use pyo3::{exceptions::PyException, intern, types::PyModule, PyErr, PyObject, PyResult, Python};

/// A Bluetooth address
pub struct Address(pub(crate) PyObject);

impl Address {
    /// The type of address
    pub fn address_type(&self) -> PyResult<AddressType> {
        Python::with_gil(|py| {
            let addr_type = self
                .0
                .getattr(py, intern!(py, "address_type"))?
                .extract::<u32>(py)?;

            let module = PyModule::import(py, intern!(py, "bumble.hci"))?;
            let klass = module.getattr(intern!(py, "Address"))?;

            if addr_type
                == klass
                    .getattr(intern!(py, "PUBLIC_DEVICE_ADDRESS"))?
                    .extract::<u32>()?
            {
                Ok(AddressType::PublicDevice)
            } else if addr_type
                == klass
                    .getattr(intern!(py, "RANDOM_DEVICE_ADDRESS"))?
                    .extract::<u32>()?
            {
                Ok(AddressType::RandomDevice)
            } else if addr_type
                == klass
                    .getattr(intern!(py, "PUBLIC_IDENTITY_ADDRESS"))?
                    .extract::<u32>()?
            {
                Ok(AddressType::PublicIdentity)
            } else if addr_type
                == klass
                    .getattr(intern!(py, "RANDOM_IDENTITY_ADDRESS"))?
                    .extract::<u32>()?
            {
                Ok(AddressType::RandomIdentity)
            } else {
                Err(PyErr::new::<PyException, _>("Invalid address type"))
            }
        })
    }

    /// True if the address is static
    pub fn is_static(&self) -> PyResult<bool> {
        Python::with_gil(|py| {
            self.0
                .getattr(py, intern!(py, "is_static"))?
                .extract::<bool>(py)
        })
    }

    /// True if the address is resolvable
    pub fn is_resolvable(&self) -> PyResult<bool> {
        Python::with_gil(|py| {
            self.0
                .getattr(py, intern!(py, "is_resolvable"))?
                .extract::<bool>(py)
        })
    }

    /// Address bytes in _little-endian_ format
    pub fn as_le_bytes(&self) -> PyResult<Vec<u8>> {
        Python::with_gil(|py| {
            self.0
                .call_method0(py, intern!(py, "to_bytes"))?
                .extract::<Vec<u8>>(py)
        })
    }

    /// Address bytes as big-endian colon-separated hex
    pub fn as_hex(&self) -> PyResult<String> {
        self.as_le_bytes().map(|bytes| {
            bytes
                .into_iter()
                .rev()
                .map(|byte| hex::encode_upper([byte]))
                .join(":")
        })
    }
}

/// BT address types
#[allow(missing_docs)]
#[derive(PartialEq, Eq, Debug)]
pub enum AddressType {
    PublicDevice,
    RandomDevice,
    PublicIdentity,
    RandomIdentity,
}
