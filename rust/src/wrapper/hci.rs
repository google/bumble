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

// re-export here, and internal usages of these imports should refer to this mod, not the internal
// mod
pub(crate) use crate::internal::hci::WithPacketType;
pub use crate::internal::hci::{packets, Error, Packet};

use crate::wrapper::{
    hci::packets::{AddressType, Command, ErrorCode},
    ConversionError,
};
use itertools::Itertools as _;
use pyo3::{
    exceptions::PyException, intern, types::PyModule, FromPyObject, IntoPy, PyAny, PyErr, PyObject,
    PyResult, Python, ToPyObject,
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

/// Bumble's representation of an HCI command.
pub(crate) struct HciCommand(pub(crate) PyObject);

impl HciCommand {
    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        Python::with_gil(|py| {
            PyModule::import(py, intern!(py, "bumble.hci"))?
                .getattr(intern!(py, "HCI_Command"))?
                .call_method1(intern!(py, "from_bytes"), (bytes,))
                .map(|obj| Self(obj.to_object(py)))
        })
    }
}

impl TryFrom<Command> for HciCommand {
    type Error = PyErr;

    fn try_from(value: Command) -> Result<Self, Self::Error> {
        HciCommand::from_bytes(&value.to_vec_with_packet_type())
    }
}

impl IntoPy<PyObject> for HciCommand {
    fn into_py(self, _py: Python<'_>) -> PyObject {
        self.0
    }
}

/// A Bluetooth address
#[derive(Clone)]
pub struct Address(pub(crate) PyObject);

impl Address {
    /// Creates a new [Address] object.
    pub fn new(address: &str, address_type: AddressType) -> PyResult<Self> {
        Python::with_gil(|py| {
            PyModule::import(py, intern!(py, "bumble.device"))?
                .getattr(intern!(py, "Address"))?
                .call1((address, address_type))
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

/// An error meaning that the u64 value did not represent a valid BT address.
#[derive(Debug)]
pub struct InvalidAddress(u64);

impl TryInto<packets::Address> for Address {
    type Error = ConversionError<InvalidAddress>;

    fn try_into(self) -> Result<packets::Address, Self::Error> {
        let addr_le_bytes = self.as_le_bytes().map_err(ConversionError::Python)?;

        // packets::Address only supports converting from a u64 (TODO: update if/when it supports converting from [u8; 6] -- https://github.com/google/pdl/issues/75)
        // So first we take the python `Address` little-endian bytes (6 bytes), copy them into a
        // [u8; 8] in little-endian format, and finally convert it into a u64.
        let mut buf = [0_u8; 8];
        buf[0..6].copy_from_slice(&addr_le_bytes);
        let address_u64 = u64::from_le_bytes(buf);

        packets::Address::try_from(address_u64)
            .map_err(InvalidAddress)
            .map_err(ConversionError::Native)
    }
}

impl IntoPy<PyObject> for AddressType {
    fn into_py(self, py: Python<'_>) -> PyObject {
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
