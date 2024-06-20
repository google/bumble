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

use itertools::Itertools;
pub use pdl_runtime::{Error, Packet};
use std::fmt;

use crate::internal::hci::packets::{Acl, AddressType, Command, Event, Sco};
use pdl_derive::pdl;

#[allow(missing_docs, warnings, clippy::all)]
#[pdl("src/internal/hci/packets.pdl")]
pub mod packets {}
#[cfg(test)]
mod tests;

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
        self.address_type == AddressType::RandomDeviceAddress && self.le_bytes[5] >> 6 == 1
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

/// Error type for [Address::from_be_hex].
#[derive(Debug, thiserror::Error)]
#[error("Invalid address hex: {address}")]
pub struct InvalidAddressHex<'a> {
    address: &'a str,
}

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
    PacketParse { error: Error },
}

impl From<Error> for PacketTypeParseError {
    fn from(error: Error) -> Self {
        Self::PacketParse { error }
    }
}

impl WithPacketType<Self> for Command {
    fn to_vec_with_packet_type(self) -> Vec<u8> {
        prepend_packet_type(PacketType::Command, self)
    }

    fn parse_with_packet_type(bytes: &[u8]) -> Result<Self, PacketTypeParseError> {
        parse_with_expected_packet_type(Command::parse, PacketType::Command, bytes)
    }
}

impl WithPacketType<Self> for Acl {
    fn to_vec_with_packet_type(self) -> Vec<u8> {
        prepend_packet_type(PacketType::Acl, self)
    }

    fn parse_with_packet_type(bytes: &[u8]) -> Result<Self, PacketTypeParseError> {
        parse_with_expected_packet_type(Acl::parse, PacketType::Acl, bytes)
    }
}

impl WithPacketType<Self> for Sco {
    fn to_vec_with_packet_type(self) -> Vec<u8> {
        prepend_packet_type(PacketType::Sco, self)
    }

    fn parse_with_packet_type(bytes: &[u8]) -> Result<Self, PacketTypeParseError> {
        parse_with_expected_packet_type(Sco::parse, PacketType::Sco, bytes)
    }
}

impl WithPacketType<Self> for Event {
    fn to_vec_with_packet_type(self) -> Vec<u8> {
        prepend_packet_type(PacketType::Event, self)
    }

    fn parse_with_packet_type(bytes: &[u8]) -> Result<Self, PacketTypeParseError> {
        parse_with_expected_packet_type(Event::parse, PacketType::Event, bytes)
    }
}

fn prepend_packet_type<T: Packet>(packet_type: PacketType, packet: T) -> Vec<u8> {
    // TODO: refactor if `pdl` crate adds API for writing into buffer (github.com/google/pdl/issues/74)
    let mut packet_bytes = packet.to_vec();
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
