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

use crate::internal::hci::packets::{Acl, Command, Error, Event, Packet, Sco};
use pdl_derive::pdl;

#[allow(missing_docs, warnings, clippy::all)]
#[pdl("src/internal/hci/packets.pdl")]
pub mod packets {}
#[cfg(test)]
mod tests;

/// HCI Packet type, prepended to the packet.
/// Rootcanal's PDL declaration excludes this from ser/deser and instead is implemented in code.
/// To maintain the ability to easily use future versions of their packet PDL, packet type is
/// implemented here.
#[derive(Debug, PartialEq)]
pub(crate) enum PacketType {
    Command = 0x01,
    Acl = 0x02,
    Sco = 0x03,
    Event = 0x04,
}

impl TryFrom<u8> for PacketType {
    type Error = PacketTypeParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(PacketType::Command),
            0x02 => Ok(PacketType::Acl),
            0x03 => Ok(PacketType::Sco),
            0x04 => Ok(PacketType::Event),
            _ => Err(PacketTypeParseError::InvalidPacketType { value }),
        }
    }
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

/// Allows for smoother interoperability between a [Packet] and a bytes representation of it that
/// includes its type as a header
pub(crate) trait WithPacketType<T: Packet> {
    /// Converts the [Packet] into bytes, prefixed with its type
    fn to_vec_with_packet_type(self) -> Vec<u8>;

    /// Parses a [Packet] out of bytes that are prefixed with the packet's type
    fn parse_with_packet_type(bytes: &[u8]) -> Result<T, PacketTypeParseError>;
}

/// Errors that may arise when parsing a packet that is prefixed with its type
#[derive(Debug, PartialEq, thiserror::Error)]
pub(crate) enum PacketTypeParseError {
    #[error("The slice being parsed was empty")]
    EmptySlice,
    #[error("Packet type ({value:#X}) is invalid")]
    InvalidPacketType { value: u8 },
    #[error("Expected packet type: {expected:?}, but got: {actual:?}")]
    PacketTypeMismatch {
        expected: PacketType,
        actual: PacketType,
    },
    #[error("Failed to parse packet after header: {error}")]
    PacketParse { error: packets::Error },
}

// TODO: remove if/when PDL derives this for their Error enum (https://github.com/google/pdl/issues/71)
impl PartialEq<Self> for packets::Error {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Error::InvalidPacketError, Error::InvalidPacketError) => true,
            (
                Error::ConstraintOutOfBounds {
                    field: field1,
                    value: value1,
                },
                Error::ConstraintOutOfBounds {
                    field: field2,
                    value: value2,
                },
            ) => field1 == field2 && value1 == value2,
            (
                Error::InvalidFixedValue {
                    expected: expected1,
                    actual: actual1,
                },
                Error::InvalidFixedValue {
                    expected: expected2,
                    actual: actual2,
                },
            ) => expected1 == expected2 && actual1 == actual2,
            (
                Error::InvalidLengthError {
                    obj: obj1,
                    wanted: wanted1,
                    got: got1,
                },
                Error::InvalidLengthError {
                    obj: obj2,
                    wanted: wanted2,
                    got: got2,
                },
            ) => obj1 == obj2 && wanted1 == wanted2 && got1 == got2,
            (
                Error::InvalidArraySize {
                    array: array1,
                    element: element1,
                },
                Error::InvalidArraySize {
                    array: array2,
                    element: element2,
                },
            ) => array1 == array2 && element1 == element2,
            (Error::ImpossibleStructError, Error::ImpossibleStructError) => true,
            (
                Error::InvalidEnumValueError {
                    obj: obj1,
                    field: field1,
                    value: value1,
                    type_: type_1,
                },
                Error::InvalidEnumValueError {
                    obj: obj2,
                    field: field2,
                    value: value2,
                    type_: type_2,
                },
            ) => obj1 == obj2 && field1 == field2 && value1 == value2 && type_1 == type_2,
            (
                Error::InvalidChildError {
                    expected: expected1,
                    actual: actual1,
                },
                Error::InvalidChildError {
                    expected: expected2,
                    actual: actual2,
                },
            ) => expected1 == expected2 && actual1 == actual2,
            _ => false,
        }
    }
}

impl From<packets::Error> for PacketTypeParseError {
    fn from(error: Error) -> Self {
        Self::PacketParse { error }
    }
}

impl WithPacketType<Self> for Command {
    fn to_vec_with_packet_type(self) -> Vec<u8> {
        prepend_packet_type(PacketType::Command, self.to_vec())
    }

    fn parse_with_packet_type(bytes: &[u8]) -> Result<Self, PacketTypeParseError> {
        parse_with_expected_packet_type(Command::parse, PacketType::Command, bytes)
    }
}

impl WithPacketType<Self> for Acl {
    fn to_vec_with_packet_type(self) -> Vec<u8> {
        prepend_packet_type(PacketType::Acl, self.to_vec())
    }

    fn parse_with_packet_type(bytes: &[u8]) -> Result<Self, PacketTypeParseError> {
        parse_with_expected_packet_type(Acl::parse, PacketType::Acl, bytes)
    }
}

impl WithPacketType<Self> for Sco {
    fn to_vec_with_packet_type(self) -> Vec<u8> {
        prepend_packet_type(PacketType::Sco, self.to_vec())
    }

    fn parse_with_packet_type(bytes: &[u8]) -> Result<Self, PacketTypeParseError> {
        parse_with_expected_packet_type(Sco::parse, PacketType::Sco, bytes)
    }
}

impl WithPacketType<Self> for Event {
    fn to_vec_with_packet_type(self) -> Vec<u8> {
        prepend_packet_type(PacketType::Event, self.to_vec())
    }

    fn parse_with_packet_type(bytes: &[u8]) -> Result<Self, PacketTypeParseError> {
        parse_with_expected_packet_type(Event::parse, PacketType::Event, bytes)
    }
}

fn prepend_packet_type(packet_type: PacketType, mut packet_bytes: Vec<u8>) -> Vec<u8> {
    packet_bytes.insert(0, packet_type.into());
    packet_bytes
}

fn parse_with_expected_packet_type<T: Packet, F, E>(
    parser: F,
    expected_packet_type: PacketType,
    bytes: &[u8],
) -> Result<T, PacketTypeParseError>
where
    F: Fn(&[u8]) -> Result<T, E>,
    PacketTypeParseError: From<E>,
{
    let (first_byte, packet_bytes) = bytes
        .split_first()
        .ok_or(PacketTypeParseError::EmptySlice)?;
    let actual_packet_type = PacketType::try_from(*first_byte)?;
    if actual_packet_type == expected_packet_type {
        Ok(parser(packet_bytes)?)
    } else {
        Err(PacketTypeParseError::PacketTypeMismatch {
            expected: expected_packet_type,
            actual: actual_packet_type,
        })
    }
}
