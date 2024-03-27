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

use std::fmt;
// re-export here, and internal usages of these imports should refer to this mod, not the internal
// mod
pub(crate) use crate::internal::hci::WithPacketType;
pub use crate::internal::hci::{packets, Error, Packet};

use crate::wrapper::core::{TryFromPy, TryToPy};
use crate::wrapper::hci::packets::{AddressType, Command, ErrorCode};
use itertools::Itertools as _;
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

/// A Bluetooth address
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address {
    /// Little-endian bytes
    le_bytes: [u8; 6],
    address_type: AddressType,
}

impl Address {
    /// Creates a new address with the provided little-endian bytes.
    pub fn from_le_bytes(le_bytes: [u8; 6], address_type: AddressType) -> Self {
        Self {
            le_bytes,
            address_type,
        }
    }

    /// Creates a new address with the provided big endian hex (with or without `:` separators).
    ///
    /// # Examples
    ///
    /// ```
    /// use bumble::{wrapper::{hci::{Address, packets::AddressType}}};
    /// let hex = "F0:F1:F2:F3:F4:F5";
    /// assert_eq!(
    ///     hex,
    ///     Address::from_be_hex(hex, AddressType::PublicDeviceAddress).unwrap().as_be_hex()
    /// );
    /// ```
    pub fn from_be_hex(
        address: &str,
        address_type: AddressType,
    ) -> Result<Self, InvalidAddressHex> {
        let filtered: String = address.chars().filter(|c| *c != ':').collect();
        let mut bytes: [u8; 6] = hex::decode(filtered)
            .map_err(|_| InvalidAddressHex { address })?
            .try_into()
            .map_err(|_| InvalidAddressHex { address })?;
        bytes.reverse();

        Ok(Self {
            le_bytes: bytes,
            address_type,
        })
    }

    /// The type of address
    pub fn address_type(&self) -> AddressType {
        self.address_type
    }

    /// True if the address is static
    pub fn is_static(&self) -> bool {
        !self.is_public() && self.le_bytes[5] >> 6 == 3
    }

    /// True if the address type is [AddressType::PublicIdentityAddress] or
    /// [AddressType::PublicDeviceAddress]
    pub fn is_public(&self) -> bool {
        matches!(
            self.address_type,
            AddressType::PublicDeviceAddress | AddressType::PublicIdentityAddress
        )
    }

    /// True if the address is resolvable
    pub fn is_resolvable(&self) -> bool {
        matches!(
            self.address_type,
            AddressType::PublicIdentityAddress | AddressType::RandomIdentityAddress
        )
    }

    /// Address bytes in _little-endian_ format
    pub fn as_le_bytes(&self) -> [u8; 6] {
        self.le_bytes
    }

    /// Address bytes as big-endian colon-separated hex
    pub fn as_be_hex(&self) -> String {
        self.le_bytes
            .into_iter()
            .rev()
            .map(|byte| hex::encode_upper([byte]))
            .join(":")
    }
}

// show a more readable form than default Debug for a byte array
impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Address {{ address: {}, type: {:?} }}",
            self.as_be_hex(),
            self.address_type
        )
    }
}

impl TryToPy for Address {
    fn try_to_py<'py>(&self, py: Python<'py>) -> PyResult<&'py PyAny> {
        PyModule::import(py, intern!(py, "bumble.device"))?
            .getattr(intern!(py, "Address"))?
            .call1((PyBytes::new(py, &self.le_bytes), self.address_type))
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

        Ok(Self {
            le_bytes: address,
            address_type,
        })
    }
}

/// Error type for [Address::from_be_hex].
#[derive(Debug, thiserror::Error)]
#[error("Invalid address hex: {address}")]
pub struct InvalidAddressHex<'a> {
    address: &'a str,
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
