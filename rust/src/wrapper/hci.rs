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

//! HCI

// re-export here, and internal usages of these imports should refer to this mod, not the internal
// mod
pub(crate) use crate::internal::hci::WithPacketType;
pub use crate::internal::hci::{packets, Address, Error, InvalidAddressHex, Packet};

use crate::wrapper::core::{TryFromPy, TryToPy};
use crate::wrapper::hci::packets::{AddressType, Command, ErrorCode};
use pyo3::types::PyBytes;
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

impl TryToPy for Address {
    fn try_to_py<'py>(&self, py: Python<'py>) -> PyResult<&'py PyAny> {
        PyModule::import(py, intern!(py, "bumble.device"))?
            .getattr(intern!(py, "Address"))?
            .call1((PyBytes::new(py, &self.as_le_bytes()), self.address_type()))
    }
}

impl TryFromPy for Address {
    fn try_from_py<'py>(py: Python<'py>, obj: &'py PyAny) -> PyResult<Self> {
        let address_type = obj
            .getattr(intern!(py, "address_type"))?
            .extract::<u8>()?
            .try_into()
            .map_err(|addr_type| {
                PyErr::new::<PyException, _>(format!(
                    "Failed to convert {addr_type} to AddressType"
                ))
            })?;

        let address = obj.call_method0(intern!(py, "to_bytes"))?.extract()?;

        Ok(Self::from_le_bytes(address, address_type))
    }
}

/// An error meaning that the internal u64 value used to convert to [packets::Address] did not
/// represent a valid BT address.
#[derive(Debug, thiserror::Error)]
#[error("Invalid address u64: {0}")]
pub struct AddressConversionError(#[allow(unused)] u64);

impl TryInto<packets::Address> for Address {
    type Error = AddressConversionError;

    fn try_into(self) -> Result<packets::Address, Self::Error> {
        // packets::Address only supports converting from a u64 (TODO: update if/when it supports converting from [u8; 6] -- https://github.com/google/pdl/issues/75)
        // So first we take the python `Address` little-endian bytes (6 bytes), copy them into a
        // [u8; 8] in little-endian format, and finally convert it into a u64.
        let mut buf = [0_u8; 8];
        buf[0..6].copy_from_slice(&self.as_le_bytes());
        let address_u64 = u64::from_le_bytes(buf);

        packets::Address::try_from(address_u64).map_err(AddressConversionError)
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
