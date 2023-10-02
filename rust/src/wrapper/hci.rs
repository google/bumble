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

pub use crate::internal::hci::{packets, Error, Packet};

use crate::{
    internal::hci::WithPacketType,
    wrapper::hci::packets::{AddressType, Command, ErrorCode},
};
use itertools::Itertools as _;
use pyo3::{
    exceptions::PyException,
    intern, pyclass, pymethods,
    types::{PyBytes, PyModule},
    FromPyObject, IntoPy, PyAny, PyErr, PyObject, PyResult, Python, ToPyObject,
};

/// Provides helpers for interacting with HCI
pub struct HciConstant;

impl HciConstant {
    /// Human-readable error name
    pub fn error_name(status: ErrorCode) -> PyResult<String> {
        Python::with_gil(|py| {
            PyModule::import(py, intern!(py, "bumble.hci"))?
                .getattr(intern!(py, "HCI_Constant"))?
                .call_method1(intern!(py, "error_name"), (status.to_object(py),))?
                .extract()
        })
    }
}

/// A Bluetooth address
#[derive(Clone)]
pub struct Address(pub(crate) PyObject);

impl Address {
    /// Creates a new [Address] object
    pub fn new(address: &str, address_type: &AddressType) -> PyResult<Self> {
        Python::with_gil(|py| {
            PyModule::import(py, intern!(py, "bumble.device"))?
                .getattr(intern!(py, "Address"))?
                .call1((address, address_type.to_object(py)))
                .map(|any| Self(any.into()))
        })
    }

    /// The type of address
    pub fn address_type(&self) -> PyResult<AddressType> {
        Python::with_gil(|py| {
            self.0
                .getattr(py, intern!(py, "address_type"))?
                .extract::<u8>(py)?
                .try_into()
                .map_err(|addr_type| {
                    PyErr::new::<PyException, _>(format!(
                        "Failed to convert {addr_type} to AddressType"
                    ))
                })
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

impl ToPyObject for Address {
    fn to_object(&self, _py: Python<'_>) -> PyObject {
        self.0.clone()
    }
}

/// Implements minimum necessary interface to be treated as bumble's [HCI_Command].
/// While pyo3's macros do not support generics, this could probably be refactored to allow multiple
/// implementations of the HCI_Command methods in the future, if needed.
#[pyclass]
pub(crate) struct HciCommandWrapper(pub(crate) Command);

#[pymethods]
impl HciCommandWrapper {
    fn __bytes__(&self, py: Python) -> PyResult<PyObject> {
        let bytes = PyBytes::new(py, &self.0.clone().to_vec_with_packet_type());
        Ok(bytes.into_py(py))
    }

    #[getter]
    fn op_code(&self) -> u16 {
        self.0.get_op_code().into()
    }
}

impl ToPyObject for AddressType {
    fn to_object(&self, py: Python<'_>) -> PyObject {
        u8::from(self).to_object(py)
    }
}

impl<'source> FromPyObject<'source> for ErrorCode {
    fn extract(ob: &'source PyAny) -> PyResult<Self> {
        ob.extract()
    }
}

impl ToPyObject for ErrorCode {
    fn to_object(&self, py: Python<'_>) -> PyObject {
        u8::from(self).to_object(py)
    }
}
