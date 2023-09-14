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

pub use crate::internal::hci::packets;

use crate::wrapper::hci::packets::{
    Acl, AddressType, Command, Error, ErrorCode, Event, Packet, Sco,
};
use itertools::Itertools as _;
use pyo3::{
    exceptions::PyException,
    intern, pyclass, pymethods,
    types::{PyBytes, PyModule},
    FromPyObject, IntoPy, PyAny, PyErr, PyObject, PyResult, Python, ToPyObject,
};
use std::fmt::{Display, Formatter};

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

/// HCI Packet type, prepended to the packet.
/// Rootcanal's PDL declaration excludes this from ser/deser and instead is implemented in code.
/// To maintain the ability to easily use future versions of their packet PDL, packet type is
/// implemented here.
#[derive(Debug)]
pub(crate) enum PacketType {
    Command = 0x01,
    Acl = 0x02,
    Sco = 0x03,
    Event = 0x04,
}

impl From<PacketType> for u8 {
    fn from(packet_type: PacketType) -> Self {
        match packet_type {
            PacketType::Command => 0x01,
            PacketType::Acl => 0x02,
            PacketType::Sco => 0x03,
            PacketType::Event => 0x04,
        }
    }
}

impl TryFrom<u8> for PacketType {
    type Error = PacketTypeParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(PacketType::Command),
            0x02 => Ok(PacketType::Acl),
            0x03 => Ok(PacketType::Sco),
            0x04 => Ok(PacketType::Event),
            _ => Err(PacketTypeParseError::NonexistentPacketType(value)),
        }
    }
}

/// Allows for smoother interoperability between a [Packet] and a bytes representation of it that
/// includes its type as a header
pub(crate) trait WithPacketType<T: Packet> {
    /// Converts the [Packet] into bytes, prefixed with its type
    fn to_vec_with_packet_type(self) -> Vec<u8>;

    /// Parses a [Packet] out of bytes that are prefixed with the packet's type
    fn parse_with_packet_type(bytes: &[u8]) -> Result<T, PacketTypeParseError>;
}

/// Errors that may arise when parsing a packet that is prefixed with its type
pub(crate) enum PacketTypeParseError {
    EmptySlice,
    NoPacketBytes,
    PacketTypeMismatch {
        expected: PacketType,
        actual: PacketType,
    },
    NonexistentPacketType(u8),
    PacketParse(packets::Error),
}

impl Display for PacketTypeParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketTypeParseError::EmptySlice => write!(f, "The slice being parsed was empty"),
            PacketTypeParseError::NoPacketBytes => write!(
                f,
                "There were no bytes left after parsing the packet type header"
            ),
            PacketTypeParseError::PacketTypeMismatch { expected, actual } => {
                write!(f, "Expected type: {expected:?}, but got: {actual:?}")
            }
            PacketTypeParseError::NonexistentPacketType(packet_byte) => {
                write!(f, "Packet type ({packet_byte:X}) does not exist")
            }
            PacketTypeParseError::PacketParse(e) => f.write_str(&e.to_string()),
        }
    }
}

impl From<packets::Error> for PacketTypeParseError {
    fn from(value: Error) -> Self {
        Self::PacketParse(value)
    }
}

impl WithPacketType<Self> for Command {
    fn to_vec_with_packet_type(self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        bytes.push(PacketType::Command.into());
        bytes.append(&mut self.to_vec());
        bytes
    }

    fn parse_with_packet_type(bytes: &[u8]) -> Result<Self, PacketTypeParseError> {
        let first_byte = bytes.first().ok_or(PacketTypeParseError::EmptySlice)?;
        match PacketType::try_from(*first_byte)? {
            PacketType::Command => {
                let packet_bytes = bytes.get(1..).ok_or(PacketTypeParseError::NoPacketBytes)?;
                Ok(Command::parse(packet_bytes)?)
            }
            packet_type => Err(PacketTypeParseError::PacketTypeMismatch {
                expected: PacketType::Command,
                actual: packet_type,
            }),
        }
    }
}

impl WithPacketType<Self> for Acl {
    fn to_vec_with_packet_type(self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        bytes.push(PacketType::Acl.into());
        bytes.append(&mut self.to_vec());
        bytes
    }

    fn parse_with_packet_type(bytes: &[u8]) -> Result<Self, PacketTypeParseError> {
        let first_byte = bytes.first().ok_or(PacketTypeParseError::EmptySlice)?;
        match PacketType::try_from(*first_byte)? {
            PacketType::Acl => {
                let packet_bytes = bytes.get(1..).ok_or(PacketTypeParseError::NoPacketBytes)?;
                Ok(Acl::parse(packet_bytes)?)
            }
            packet_type => Err(PacketTypeParseError::PacketTypeMismatch {
                expected: PacketType::Acl,
                actual: packet_type,
            }),
        }
    }
}

impl WithPacketType<Self> for Sco {
    fn to_vec_with_packet_type(self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        bytes.push(PacketType::Sco.into());
        bytes.append(&mut self.to_vec());
        bytes
    }

    fn parse_with_packet_type(bytes: &[u8]) -> Result<Self, PacketTypeParseError> {
        let first_byte = bytes.first().ok_or(PacketTypeParseError::EmptySlice)?;
        match PacketType::try_from(*first_byte)? {
            PacketType::Sco => {
                let packet_bytes = bytes.get(1..).ok_or(PacketTypeParseError::NoPacketBytes)?;
                Ok(Sco::parse(packet_bytes)?)
            }
            packet_type => Err(PacketTypeParseError::PacketTypeMismatch {
                expected: PacketType::Sco,
                actual: packet_type,
            }),
        }
    }
}

impl WithPacketType<Self> for Event {
    fn to_vec_with_packet_type(self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        bytes.push(PacketType::Event.into());
        bytes.append(&mut self.to_vec());
        bytes
    }

    fn parse_with_packet_type(bytes: &[u8]) -> Result<Self, PacketTypeParseError> {
        let first_byte = bytes.first().ok_or(PacketTypeParseError::EmptySlice)?;
        match PacketType::try_from(*first_byte)? {
            PacketType::Event => {
                let packet_bytes = bytes.get(1..).ok_or(PacketTypeParseError::NoPacketBytes)?;
                Ok(Event::parse(packet_bytes)?)
            }
            packet_type => Err(PacketTypeParseError::PacketTypeMismatch {
                expected: PacketType::Event,
                actual: packet_type,
            }),
        }
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
