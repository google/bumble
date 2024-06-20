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

use crate::internal::adv::AdvertisementDataValue;
use lazy_static::lazy_static;
use nom::combinator;
use std::fmt;

lazy_static! {
    static ref BASE_UUID: [u8; 16] = hex::decode("0000000000001000800000805F9B34FB")
        .unwrap()
        .try_into()
        .unwrap();
}

/// 16-bit UUID
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct Uuid16 {
    /// Big-endian bytes
    be_bytes: [u8; 2],
}

impl Uuid16 {
    /// Construct a UUID from little-endian bytes
    pub fn from_le_bytes(mut le_bytes: [u8; 2]) -> Self {
        le_bytes.reverse();
        Self::from_be_bytes(le_bytes)
    }

    /// Construct a UUID from big-endian bytes
    pub const fn from_be_bytes(be_bytes: [u8; 2]) -> Self {
        Self { be_bytes }
    }

    /// The UUID in big-endian bytes form
    pub fn as_be_bytes(&self) -> [u8; 2] {
        self.be_bytes
    }

    /// The UUID in little-endian bytes form
    pub fn as_le_bytes(&self) -> [u8; 2] {
        let mut uuid = self.be_bytes;
        uuid.reverse();
        uuid
    }

    pub(crate) fn parse_le(input: &[u8]) -> nom::IResult<&[u8], Self> {
        combinator::map_res(nom::bytes::complete::take(2_usize), |b: &[u8]| {
            b.try_into().map(|mut uuid: [u8; 2]| {
                uuid.reverse();
                Self { be_bytes: uuid }
            })
        })(input)
    }
}

impl From<u16> for Uuid16 {
    fn from(value: u16) -> Self {
        Self {
            be_bytes: value.to_be_bytes(),
        }
    }
}

impl fmt::Debug for Uuid16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UUID-16:{}", hex::encode_upper(self.be_bytes))
    }
}

impl AdvertisementDataValue for Uuid16 {
    fn write_to(&self, buf: &mut impl bytes::BufMut) {
        buf.put(self.as_le_bytes().as_slice())
    }
}

/// 32-bit UUID
#[derive(PartialEq, Eq, Hash)]
pub struct Uuid32 {
    /// Big-endian bytes
    be_bytes: [u8; 4],
}

impl Uuid32 {
    /// The UUID in big-endian bytes form
    pub fn as_be_bytes(&self) -> [u8; 4] {
        self.be_bytes
    }

    pub(crate) fn parse(input: &[u8]) -> nom::IResult<&[u8], Self> {
        combinator::map_res(nom::bytes::complete::take(4_usize), |b: &[u8]| {
            b.try_into().map(|mut uuid: [u8; 4]| {
                uuid.reverse();
                Self { be_bytes: uuid }
            })
        })(input)
    }
}

impl fmt::Debug for Uuid32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UUID-32:{}", hex::encode_upper(self.be_bytes))
    }
}

impl From<Uuid16> for Uuid32 {
    fn from(value: Uuid16) -> Self {
        let mut uuid = [0; 4];
        uuid[2..].copy_from_slice(&value.be_bytes);
        Self { be_bytes: uuid }
    }
}

/// 128-bit UUID
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Uuid128 {
    /// Big-endian bytes
    be_bytes: [u8; 16],
}

impl Uuid128 {
    /// The UUID in big-endian bytes form
    pub fn as_be_bytes(&self) -> [u8; 16] {
        self.be_bytes
    }
    /// The UUID in little-endian bytes form
    pub fn as_le_bytes(&self) -> [u8; 16] {
        let mut bytes = self.be_bytes;
        bytes.reverse();
        bytes
    }

    pub(crate) fn parse_le(input: &[u8]) -> nom::IResult<&[u8], Self> {
        combinator::map_res(nom::bytes::complete::take(16_usize), |b: &[u8]| {
            b.try_into().map(|mut uuid: [u8; 16]| {
                uuid.reverse();
                Self { be_bytes: uuid }
            })
        })(input)
    }

    /// Parse the normal dash-separated form of a UUID, returning None if the input is invalid
    pub fn parse_str(input: &str) -> Option<Self> {
        uuid::Uuid::parse_str(input).ok().map(|u| Self {
            be_bytes: u.into_bytes(),
        })
    }
}

impl fmt::Debug for Uuid128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}-{}-{}-{}-{}",
            hex::encode_upper(&self.be_bytes[..4]),
            hex::encode_upper(&self.be_bytes[4..6]),
            hex::encode_upper(&self.be_bytes[6..8]),
            hex::encode_upper(&self.be_bytes[8..10]),
            hex::encode_upper(&self.be_bytes[10..])
        )
    }
}

impl From<Uuid16> for Uuid128 {
    fn from(value: Uuid16) -> Self {
        let mut uuid = *BASE_UUID;
        uuid[2..4].copy_from_slice(&value.be_bytes);
        Self { be_bytes: uuid }
    }
}

impl From<Uuid32> for Uuid128 {
    fn from(value: Uuid32) -> Self {
        let mut uuid = *BASE_UUID;
        uuid[..4].copy_from_slice(&value.be_bytes);
        Self { be_bytes: uuid }
    }
}

impl AdvertisementDataValue for Uuid128 {
    fn write_to(&self, buf: &mut impl bytes::BufMut) {
        buf.put(self.as_le_bytes().as_slice())
    }
}
