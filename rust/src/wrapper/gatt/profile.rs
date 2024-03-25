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

//! GATT profiles.

use crate::internal::core::Uuid16;
use crate::wrapper::assigned_numbers::services;
use crate::wrapper::device::Peer;
use crate::wrapper::gatt::client::CharacteristicAdapter;
use anyhow::anyhow;
use pyo3::PyResult;

/// Client for the Battery GATT service.
///
/// Compare with [proxy::BatteryServiceProxy], which is a wrapper around a Python proxy.
pub struct BatteryClient {
    battery_level: CharacteristicAdapter<Vec<u8>, u8>,
}

impl BatteryClient {
    /// Construct a client for the peer, if the relevant service and characteristic are present.
    ///
    /// Service and characteristic discovery must already have been done for the peer.
    pub fn new(peer: &Peer) -> PyResult<Self> {
        let service = peer
            .services_by_uuid(services::BATTERY.uuid())?
            .into_iter()
            .next()
            .ok_or(anyhow!("Battery service not found"))?;

        let battery_level = service
            .characteristics_by_uuid(Uuid16::from(0x2A19_u16))?
            .into_iter()
            .next()
            .ok_or(anyhow!("Battery level characteristic not found"))
            .map(CharacteristicAdapter::<Vec<u8>, u8>::new)?;

        Ok(Self { battery_level })
    }

    /// Characteristic for the battery level.
    pub fn battery_level(&self) -> &CharacteristicAdapter<Vec<u8>, u8> {
        &self.battery_level
    }
}
pub mod proxy {
    //! Support for using the Python class `ProfileServiceProxy` and its subclasses.
    //!
    //! If there is already a `ProfileServiceProxy` in Python Bumble that you wish to use, implement
    //! [ProfileServiceProxy] accordingly.

    use crate::wrapper::gatt::client::CharacteristicProxy;
    use crate::wrapper::PyObjectExt;
    use pyo3::{intern, PyObject, PyResult, Python};

    /// Trait to represent Rust wrappers around Python `ProfileServiceProxy` subclasses.
    ///
    /// Used with [crate::wrapper::device::Peer::create_service_proxy].
    pub trait ProfileServiceProxy {
        /// The module containing the proxy class
        const PROXY_CLASS_MODULE: &'static str;
        /// The module class name
        const PROXY_CLASS_NAME: &'static str;

        /// Wrap a PyObject in the Rust wrapper type
        fn wrap(obj: PyObject) -> Self;
    }

    /// Wrapper around the Python `BatteryServiceProxy` class.
    pub struct BatteryServiceProxy(PyObject);

    impl BatteryServiceProxy {
        /// Get the battery level, if available
        pub fn battery_level(&self) -> PyResult<Option<CharacteristicProxy<u8>>> {
            Python::with_gil(|py| {
                self.0
                    .getattr(py, intern!(py, "battery_level"))
                    // uses `PackedCharacteristicAdapter` to expose a Python `int`
                    .map(|level| level.into_option(CharacteristicProxy::<u8>::new))
            })
        }
    }

    impl ProfileServiceProxy for BatteryServiceProxy {
        const PROXY_CLASS_MODULE: &'static str = "bumble.profiles.battery_service";
        const PROXY_CLASS_NAME: &'static str = "BatteryServiceProxy";

        fn wrap(obj: PyObject) -> Self {
            Self(obj)
        }
    }
}
