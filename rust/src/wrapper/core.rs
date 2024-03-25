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

//! Core types

pub use crate::internal::{
    adv::{AdvertisementDataBuilder, CommonDataType, CommonDataTypeCode, Flags},
    core::{Uuid128, Uuid16, Uuid32},
};
use pyo3::{intern, PyAny, PyResult, Python};

/// A type code and data pair from an advertisement
pub type AdvertisementDataUnit = (CommonDataTypeCode, Vec<u8>);

/// Contents of an advertisement
pub struct AdvertisingData {
    data_units: Vec<AdvertisementDataUnit>,
}

impl AdvertisingData {
    /// Data units in the advertisement contents
    pub fn data_units(&self) -> &[AdvertisementDataUnit] {
        &self.data_units
    }
}

impl TryFromPy for AdvertisingData {
    fn try_from_py<'py>(py: Python<'py>, obj: &'py PyAny) -> PyResult<Self> {
        let list = obj.getattr(intern!(py, "ad_structures"))?;

        list.iter()?
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
            .map(|data_units| Self { data_units })
    }
}

/// Fallibly create a [PyAny] with a provided GIL token.
pub trait TryToPy {
    /// Build a Python representation of the data in `self` using the provided GIL token `py`.
    fn try_to_py<'py>(&self, py: Python<'py>) -> PyResult<&'py PyAny>;
}

/// Fallibly extract a Rust type from a [PyAny] with a provided GIL token.
pub trait TryFromPy: Sized {
    /// Build a Rust representation of the Python object behind the [PyAny].
    fn try_from_py<'py>(py: Python<'py>, obj: &'py PyAny) -> PyResult<Self>;
}
