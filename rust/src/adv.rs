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

//! BLE advertisements.

use crate::wrapper::assigned_numbers::{COMPANY_IDS, SERVICE_IDS};
use crate::wrapper::core::{Uuid128, Uuid16, Uuid32};
use itertools::Itertools;
use nom::{combinator, multi, number};
use std::fmt;
use strum::IntoEnumIterator;

/// The numeric code for a common data type.
///
/// For known types, see [CommonDataType], or use this type directly for non-assigned codes.
#[derive(PartialEq, Eq, Debug, Clone, Copy, Hash)]
pub struct CommonDataTypeCode(u8);

impl From<CommonDataType> for CommonDataTypeCode {
    fn from(value: CommonDataType) -> Self {
        let byte = match value {
            CommonDataType::Flags => 0x01,
            CommonDataType::IncompleteListOf16BitServiceClassUuids => 0x02,
            CommonDataType::CompleteListOf16BitServiceClassUuids => 0x03,
            CommonDataType::IncompleteListOf32BitServiceClassUuids => 0x04,
            CommonDataType::CompleteListOf32BitServiceClassUuids => 0x05,
            CommonDataType::IncompleteListOf128BitServiceClassUuids => 0x06,
            CommonDataType::CompleteListOf128BitServiceClassUuids => 0x07,
            CommonDataType::ShortenedLocalName => 0x08,
            CommonDataType::CompleteLocalName => 0x09,
            CommonDataType::TxPowerLevel => 0x0A,
            CommonDataType::ClassOfDevice => 0x0D,
            CommonDataType::SimplePairingHashC192 => 0x0E,
            CommonDataType::SimplePairingRandomizerR192 => 0x0F,
            // These two both really have type code 0x10! D:
            CommonDataType::DeviceId => 0x10,
            CommonDataType::SecurityManagerTkValue => 0x10,
            CommonDataType::SecurityManagerOutOfBandFlags => 0x11,
            CommonDataType::PeripheralConnectionIntervalRange => 0x12,
            CommonDataType::ListOf16BitServiceSolicitationUuids => 0x14,
            CommonDataType::ListOf128BitServiceSolicitationUuids => 0x15,
            CommonDataType::ServiceData16BitUuid => 0x16,
            CommonDataType::PublicTargetAddress => 0x17,
            CommonDataType::RandomTargetAddress => 0x18,
            CommonDataType::Appearance => 0x19,
            CommonDataType::AdvertisingInterval => 0x1A,
            CommonDataType::LeBluetoothDeviceAddress => 0x1B,
            CommonDataType::LeRole => 0x1C,
            CommonDataType::SimplePairingHashC256 => 0x1D,
            CommonDataType::SimplePairingRandomizerR256 => 0x1E,
            CommonDataType::ListOf32BitServiceSolicitationUuids => 0x1F,
            CommonDataType::ServiceData32BitUuid => 0x20,
            CommonDataType::ServiceData128BitUuid => 0x21,
            CommonDataType::LeSecureConnectionsConfirmationValue => 0x22,
            CommonDataType::LeSecureConnectionsRandomValue => 0x23,
            CommonDataType::Uri => 0x24,
            CommonDataType::IndoorPositioning => 0x25,
            CommonDataType::TransportDiscoveryData => 0x26,
            CommonDataType::LeSupportedFeatures => 0x27,
            CommonDataType::ChannelMapUpdateIndication => 0x28,
            CommonDataType::PbAdv => 0x29,
            CommonDataType::MeshMessage => 0x2A,
            CommonDataType::MeshBeacon => 0x2B,
            CommonDataType::BigInfo => 0x2C,
            CommonDataType::BroadcastCode => 0x2D,
            CommonDataType::ResolvableSetIdentifier => 0x2E,
            CommonDataType::AdvertisingIntervalLong => 0x2F,
            CommonDataType::ThreeDInformationData => 0x3D,
            CommonDataType::ManufacturerSpecificData => 0xFF,
        };

        Self(byte)
    }
}

impl From<u8> for CommonDataTypeCode {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<CommonDataTypeCode> for u8 {
    fn from(value: CommonDataTypeCode) -> Self {
        value.0
    }
}

/// Data types for assigned type codes.
///
/// See Bluetooth Assigned Numbers § 2.3
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum_macros::EnumIter)]
#[allow(missing_docs)]
pub enum CommonDataType {
    Flags,
    IncompleteListOf16BitServiceClassUuids,
    CompleteListOf16BitServiceClassUuids,
    IncompleteListOf32BitServiceClassUuids,
    CompleteListOf32BitServiceClassUuids,
    IncompleteListOf128BitServiceClassUuids,
    CompleteListOf128BitServiceClassUuids,
    ShortenedLocalName,
    CompleteLocalName,
    TxPowerLevel,
    ClassOfDevice,
    SimplePairingHashC192,
    SimplePairingRandomizerR192,
    DeviceId,
    SecurityManagerTkValue,
    SecurityManagerOutOfBandFlags,
    PeripheralConnectionIntervalRange,
    ListOf16BitServiceSolicitationUuids,
    ListOf128BitServiceSolicitationUuids,
    ServiceData16BitUuid,
    PublicTargetAddress,
    RandomTargetAddress,
    Appearance,
    AdvertisingInterval,
    LeBluetoothDeviceAddress,
    LeRole,
    SimplePairingHashC256,
    SimplePairingRandomizerR256,
    ListOf32BitServiceSolicitationUuids,
    ServiceData32BitUuid,
    ServiceData128BitUuid,
    LeSecureConnectionsConfirmationValue,
    LeSecureConnectionsRandomValue,
    Uri,
    IndoorPositioning,
    TransportDiscoveryData,
    LeSupportedFeatures,
    ChannelMapUpdateIndication,
    PbAdv,
    MeshMessage,
    MeshBeacon,
    BigInfo,
    BroadcastCode,
    ResolvableSetIdentifier,
    AdvertisingIntervalLong,
    ThreeDInformationData,
    ManufacturerSpecificData,
}

impl CommonDataType {
    /// Iterate over the zero, one, or more matching types for the provided code.
    ///
    /// `0x10` maps to both Device Id and Security Manager TK Value, so multiple matching types
    /// may exist for a single code.
    pub fn for_type_code(code: CommonDataTypeCode) -> impl Iterator<Item = CommonDataType> {
        Self::iter().filter(move |t| CommonDataTypeCode::from(*t) == code)
    }

    /// Apply type-specific human-oriented formatting to data, if any is applicable
    pub fn format_data(&self, data: &[u8]) -> Option<String> {
        match self {
            Self::Flags => Some(Flags::matching(data).map(|f| format!("{:?}", f)).join(",")),
            Self::CompleteListOf16BitServiceClassUuids
            | Self::IncompleteListOf16BitServiceClassUuids
            | Self::ListOf16BitServiceSolicitationUuids => {
                combinator::complete(multi::many0(Uuid16::parse_le))(data)
                    .map(|(_res, uuids)| {
                        uuids
                            .into_iter()
                            .map(|uuid| {
                                SERVICE_IDS
                                    .get(&uuid)
                                    .map(|name| format!("{:?} ({name})", uuid))
                                    .unwrap_or_else(|| format!("{:?}", uuid))
                            })
                            .join(", ")
                    })
                    .ok()
            }
            Self::CompleteListOf32BitServiceClassUuids
            | Self::IncompleteListOf32BitServiceClassUuids
            | Self::ListOf32BitServiceSolicitationUuids => {
                combinator::complete(multi::many0(Uuid32::parse))(data)
                    .map(|(_res, uuids)| uuids.into_iter().map(|u| format!("{:?}", u)).join(", "))
                    .ok()
            }
            Self::CompleteListOf128BitServiceClassUuids
            | Self::IncompleteListOf128BitServiceClassUuids
            | Self::ListOf128BitServiceSolicitationUuids => {
                combinator::complete(multi::many0(Uuid128::parse_le))(data)
                    .map(|(_res, uuids)| uuids.into_iter().map(|u| format!("{:?}", u)).join(", "))
                    .ok()
            }
            Self::ServiceData16BitUuid => Uuid16::parse_le(data)
                .map(|(rem, uuid)| {
                    format!(
                        "service={:?}, data={}",
                        SERVICE_IDS
                            .get(&uuid)
                            .map(|name| format!("{:?} ({name})", uuid))
                            .unwrap_or_else(|| format!("{:?}", uuid)),
                        hex::encode_upper(rem)
                    )
                })
                .ok(),
            Self::ServiceData32BitUuid => Uuid32::parse(data)
                .map(|(rem, uuid)| format!("service={:?}, data={}", uuid, hex::encode_upper(rem)))
                .ok(),
            Self::ServiceData128BitUuid => Uuid128::parse_le(data)
                .map(|(rem, uuid)| format!("service={:?}, data={}", uuid, hex::encode_upper(rem)))
                .ok(),
            Self::ShortenedLocalName | Self::CompleteLocalName => {
                std::str::from_utf8(data).ok().map(|s| format!("\"{}\"", s))
            }
            Self::TxPowerLevel => {
                let (_, tx) =
                    combinator::complete(number::complete::i8::<_, nom::error::Error<_>>)(data)
                        .ok()?;

                Some(tx.to_string())
            }
            Self::ManufacturerSpecificData => {
                let (rem, id) = Uuid16::parse_le(data).ok()?;
                Some(format!(
                    "company={}, data=0x{}",
                    COMPANY_IDS
                        .get(&id)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("{:?}", id)),
                    hex::encode_upper(rem)
                ))
            }
            _ => None,
        }
    }
}

impl fmt::Display for CommonDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommonDataType::Flags => write!(f, "Flags"),
            CommonDataType::IncompleteListOf16BitServiceClassUuids => {
                write!(f, "Incomplete List of 16-bit Service Class UUIDs")
            }
            CommonDataType::CompleteListOf16BitServiceClassUuids => {
                write!(f, "Complete List of 16-bit Service Class UUIDs")
            }
            CommonDataType::IncompleteListOf32BitServiceClassUuids => {
                write!(f, "Incomplete List of 32-bit Service Class UUIDs")
            }
            CommonDataType::CompleteListOf32BitServiceClassUuids => {
                write!(f, "Complete List of 32-bit Service Class UUIDs")
            }
            CommonDataType::ListOf16BitServiceSolicitationUuids => {
                write!(f, "List of 16-bit Service Solicitation UUIDs")
            }
            CommonDataType::ListOf32BitServiceSolicitationUuids => {
                write!(f, "List of 32-bit Service Solicitation UUIDs")
            }
            CommonDataType::ListOf128BitServiceSolicitationUuids => {
                write!(f, "List of 128-bit Service Solicitation UUIDs")
            }
            CommonDataType::IncompleteListOf128BitServiceClassUuids => {
                write!(f, "Incomplete List of 128-bit Service Class UUIDs")
            }
            CommonDataType::CompleteListOf128BitServiceClassUuids => {
                write!(f, "Complete List of 128-bit Service Class UUIDs")
            }
            CommonDataType::ShortenedLocalName => write!(f, "Shortened Local Name"),
            CommonDataType::CompleteLocalName => write!(f, "Complete Local Name"),
            CommonDataType::TxPowerLevel => write!(f, "TX Power Level"),
            CommonDataType::ClassOfDevice => write!(f, "Class of Device"),
            CommonDataType::SimplePairingHashC192 => {
                write!(f, "Simple Pairing Hash C-192")
            }
            CommonDataType::SimplePairingHashC256 => {
                write!(f, "Simple Pairing Hash C 256")
            }
            CommonDataType::SimplePairingRandomizerR192 => {
                write!(f, "Simple Pairing Randomizer R-192")
            }
            CommonDataType::SimplePairingRandomizerR256 => {
                write!(f, "Simple Pairing Randomizer R 256")
            }
            CommonDataType::DeviceId => write!(f, "Device Id"),
            CommonDataType::SecurityManagerTkValue => {
                write!(f, "Security Manager TK Value")
            }
            CommonDataType::SecurityManagerOutOfBandFlags => {
                write!(f, "Security Manager Out of Band Flags")
            }
            CommonDataType::PeripheralConnectionIntervalRange => {
                write!(f, "Peripheral Connection Interval Range")
            }
            CommonDataType::ServiceData16BitUuid => {
                write!(f, "Service Data 16-bit UUID")
            }
            CommonDataType::ServiceData32BitUuid => {
                write!(f, "Service Data 32-bit UUID")
            }
            CommonDataType::ServiceData128BitUuid => {
                write!(f, "Service Data 128-bit UUID")
            }
            CommonDataType::PublicTargetAddress => write!(f, "Public Target Address"),
            CommonDataType::RandomTargetAddress => write!(f, "Random Target Address"),
            CommonDataType::Appearance => write!(f, "Appearance"),
            CommonDataType::AdvertisingInterval => write!(f, "Advertising Interval"),
            CommonDataType::LeBluetoothDeviceAddress => {
                write!(f, "LE Bluetooth Device Address")
            }
            CommonDataType::LeRole => write!(f, "LE Role"),
            CommonDataType::LeSecureConnectionsConfirmationValue => {
                write!(f, "LE Secure Connections Confirmation Value")
            }
            CommonDataType::LeSecureConnectionsRandomValue => {
                write!(f, "LE Secure Connections Random Value")
            }
            CommonDataType::LeSupportedFeatures => write!(f, "LE Supported Features"),
            CommonDataType::Uri => write!(f, "URI"),
            CommonDataType::IndoorPositioning => write!(f, "Indoor Positioning"),
            CommonDataType::TransportDiscoveryData => {
                write!(f, "Transport Discovery Data")
            }
            CommonDataType::ChannelMapUpdateIndication => {
                write!(f, "Channel Map Update Indication")
            }
            CommonDataType::PbAdv => write!(f, "PB-ADV"),
            CommonDataType::MeshMessage => write!(f, "Mesh Message"),
            CommonDataType::MeshBeacon => write!(f, "Mesh Beacon"),
            CommonDataType::BigInfo => write!(f, "BIGIInfo"),
            CommonDataType::BroadcastCode => write!(f, "Broadcast Code"),
            CommonDataType::ResolvableSetIdentifier => {
                write!(f, "Resolvable Set Identifier")
            }
            CommonDataType::AdvertisingIntervalLong => {
                write!(f, "Advertising Interval Long")
            }
            CommonDataType::ThreeDInformationData => write!(f, "3D Information Data"),
            CommonDataType::ManufacturerSpecificData => {
                write!(f, "Manufacturer Specific Data")
            }
        }
    }
}

/// Accumulates advertisement data to broadcast on a [crate::wrapper::device::Device].
#[derive(Debug, Clone, Default)]
pub struct AdvertisementDataBuilder {
    encoded_data: Vec<u8>,
}

impl AdvertisementDataBuilder {
    /// Returns a new, empty instance.
    pub fn new() -> Self {
        Self {
            encoded_data: Vec::new(),
        }
    }

    /// Append advertising data to the builder.
    ///
    /// Returns an error if the data cannot be appended.
    pub fn append(
        &mut self,
        type_code: impl Into<CommonDataTypeCode>,
        data: &[u8],
    ) -> Result<(), AdvertisementDataBuilderError> {
        self.encoded_data.push(
            data.len()
                .try_into()
                .ok()
                .and_then(|len: u8| len.checked_add(1))
                .ok_or(AdvertisementDataBuilderError::DataTooLong)?,
        );
        self.encoded_data.push(type_code.into().0);
        self.encoded_data.extend_from_slice(data);

        Ok(())
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.encoded_data
    }
}

/// Errors that can occur when building advertisement data with [AdvertisementDataBuilder].
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AdvertisementDataBuilderError {
    /// The provided adv data is too long to be encoded
    #[error("Data too long")]
    DataTooLong,
}

#[derive(PartialEq, Eq, strum_macros::EnumIter)]
#[allow(missing_docs)]
/// Features in the Flags AD
pub enum Flags {
    LeLimited,
    LeDiscoverable,
    NoBrEdr,
    BrEdrController,
    BrEdrHost,
}

impl fmt::Debug for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.short_name())
    }
}

impl Flags {
    /// Iterates over the flags that are present in the provided `flags` bytes.
    pub fn matching(flags: &[u8]) -> impl Iterator<Item = Self> + '_ {
        // The encoding is not clear from the spec: do we look at the first byte? or the last?
        // In practice it's only one byte.
        let first_byte = flags.first().unwrap_or(&0_u8);

        Self::iter().filter(move |f| {
            let mask = match f {
                Flags::LeLimited => 0x01_u8,
                Flags::LeDiscoverable => 0x02,
                Flags::NoBrEdr => 0x04,
                Flags::BrEdrController => 0x08,
                Flags::BrEdrHost => 0x10,
            };

            mask & first_byte > 0
        })
    }

    /// An abbreviated form of the flag name.
    ///
    /// See [Flags::name] for the full name.
    pub fn short_name(&self) -> &'static str {
        match self {
            Flags::LeLimited => "LE Limited",
            Flags::LeDiscoverable => "LE General",
            Flags::NoBrEdr => "No BR/EDR",
            Flags::BrEdrController => "BR/EDR C",
            Flags::BrEdrHost => "BR/EDR H",
        }
    }

    /// The human-readable name of the flag.
    ///
    /// See [Flags::short_name] for a shorter string for use if compactness is important.
    pub fn name(&self) -> &'static str {
        match self {
            Flags::LeLimited => "LE Limited Discoverable Mode",
            Flags::LeDiscoverable => "LE General Discoverable Mode",
            Flags::NoBrEdr => "BR/EDR Not Supported",
            Flags::BrEdrController => "Simultaneous LE and BR/EDR (Controller)",
            Flags::BrEdrHost => "Simultaneous LE and BR/EDR (Host)",
        }
    }
}
