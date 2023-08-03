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

//! Core types

use crate::adv::CommonDataTypeCode;
use lazy_static::lazy_static;
use nom::{bytes, combinator};
use pyo3::{intern, PyObject, PyResult, Python};
use std::fmt;

lazy_static! {
    static ref BASE_UUID: [u8; 16] = hex::decode("0000000000001000800000805F9B34FB")
        .unwrap()
        .try_into()
        .unwrap();
}

/// A type code and data pair from an advertisement
pub type AdvertisementDataUnit = (CommonDataTypeCode, Vec<u8>);

/// Contents of an advertisement
pub struct AdvertisingData(pub(crate) PyObject);

impl AdvertisingData {
    /// Data units in the advertisement contents
    pub fn data_units(&self) -> PyResult<Vec<AdvertisementDataUnit>> {
        Python::with_gil(|py| {
            let list = self.0.getattr(py, intern!(py, "ad_structures"))?;

            list.as_ref(py)
                .iter()?
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .map(|tuple| {
                    let type_code = tuple
                        .call_method1(intern!(py, "__getitem__"), (0,))?
                        .extract::<u8>()?
                        .into();
                    let data = tuple
                        .call_method1(intern!(py, "__getitem__"), (1,))?
                        .extract::<Vec<u8>>()?;
                    Ok((type_code, data))
                })
                .collect::<Result<Vec<_>, _>>()
        })
    }
}

/// 16-bit UUID
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct Uuid16 {
    /// Big-endian bytes
    uuid: [u8; 2],
}

impl Uuid16 {
    /// Construct a UUID from little-endian bytes
    pub fn from_le_bytes(mut bytes: [u8; 2]) -> Self {
        bytes.reverse();
        Self::from_be_bytes(bytes)
    }

    /// Construct a UUID from big-endian bytes
    pub fn from_be_bytes(bytes: [u8; 2]) -> Self {
        Self { uuid: bytes }
    }

    /// The UUID in big-endian bytes form
    pub fn as_be_bytes(&self) -> [u8; 2] {
        self.uuid
    }

    /// The UUID in little-endian bytes form
    pub fn as_le_bytes(&self) -> [u8; 2] {
        let mut uuid = self.uuid;
        uuid.reverse();
        uuid
    }

    pub(crate) fn parse_le(input: &[u8]) -> nom::IResult<&[u8], Self> {
        combinator::map_res(bytes::complete::take(2_usize), |b: &[u8]| {
            b.try_into().map(|mut uuid: [u8; 2]| {
                uuid.reverse();
                Self { uuid }
            })
        })(input)
    }
}

impl fmt::Debug for Uuid16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UUID-16:{}", hex::encode_upper(self.uuid))
    }
}

/// 32-bit UUID
#[derive(PartialEq, Eq, Hash)]
pub struct Uuid32 {
    /// Big-endian bytes
    uuid: [u8; 4],
}

impl Uuid32 {
    /// The UUID in big-endian bytes form
    pub fn as_bytes(&self) -> [u8; 4] {
        self.uuid
    }

    pub(crate) fn parse(input: &[u8]) -> nom::IResult<&[u8], Self> {
        combinator::map_res(bytes::complete::take(4_usize), |b: &[u8]| {
            b.try_into().map(|mut uuid: [u8; 4]| {
                uuid.reverse();
                Self { uuid }
            })
        })(input)
    }
}

impl fmt::Debug for Uuid32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UUID-32:{}", hex::encode_upper(self.uuid))
    }
}

impl From<Uuid16> for Uuid32 {
    fn from(value: Uuid16) -> Self {
        let mut uuid = [0; 4];
        uuid[2..].copy_from_slice(&value.uuid);
        Self { uuid }
    }
}

/// 128-bit UUID
#[derive(PartialEq, Eq, Hash)]
pub struct Uuid128 {
    /// Big-endian bytes
    uuid: [u8; 16],
}

impl Uuid128 {
    /// The UUID in big-endian bytes form
    pub fn as_bytes(&self) -> [u8; 16] {
        self.uuid
    }

    pub(crate) fn parse_le(input: &[u8]) -> nom::IResult<&[u8], Self> {
        combinator::map_res(bytes::complete::take(16_usize), |b: &[u8]| {
            b.try_into().map(|mut uuid: [u8; 16]| {
                uuid.reverse();
                Self { uuid }
            })
        })(input)
    }
}

impl fmt::Debug for Uuid128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}-{}-{}-{}-{}",
            hex::encode_upper(&self.uuid[..4]),
            hex::encode_upper(&self.uuid[4..6]),
            hex::encode_upper(&self.uuid[6..8]),
            hex::encode_upper(&self.uuid[8..10]),
            hex::encode_upper(&self.uuid[10..])
        )
    }
}

impl From<Uuid16> for Uuid128 {
    fn from(value: Uuid16) -> Self {
        let mut uuid = *BASE_UUID;
        uuid[2..4].copy_from_slice(&value.uuid);
        Self { uuid }
    }
}

impl From<Uuid32> for Uuid128 {
    fn from(value: Uuid32) -> Self {
        let mut uuid = *BASE_UUID;
        uuid[..4].copy_from_slice(&value.uuid);
        Self { uuid }
    }
}
