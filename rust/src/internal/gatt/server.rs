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

//! Support for making GATT servers

use crate::internal::att::{AttributePermissions, AttributeRead, AttributeUuid, AttributeWrite};
use crate::internal::gatt::CharacteristicProperties;
use std::sync;

/// The UUID and characteristics for a GATT service
pub struct Service {
    pub(crate) uuid: AttributeUuid,
    pub(crate) characteristics: Vec<Characteristic>,
}

impl Service {
    /// Build a new Service with the provided uuid and characteristics.
    pub fn new(uuid: AttributeUuid, characteristics: Vec<Characteristic>) -> Self {
        Self {
            uuid,
            characteristics,
        }
    }

    /// Returns the service's UUID
    pub fn uuid(&self) -> &AttributeUuid {
        &self.uuid
    }

    /// Returns an iterator over the service's characteristics
    pub fn iter_characteristics(&self) -> impl Iterator<Item = &Characteristic> {
        self.characteristics.iter()
    }
}

/// A GATT characteristic hosted in a service
pub struct Characteristic {
    pub(crate) uuid: AttributeUuid,
    pub(crate) properties: CharacteristicProperties,
    pub(crate) permissions: AttributePermissions,
    pub(crate) value: CharacteristicValueHandler,
}

impl Characteristic {
    /// Create a new Characteristic.
    /// `properties` apply at the GATT layer.
    /// `permissions` apply to the underlying attribute holding the Characteristic Declaration at
    /// the ATT layer.
    pub fn new(
        uuid: AttributeUuid,
        properties: CharacteristicProperties,
        permissions: AttributePermissions,
        value: CharacteristicValueHandler,
    ) -> Self {
        Self {
            uuid,
            properties,
            permissions,
            value,
        }
    }

    /// Returns the UUID of the characteristic
    pub fn uuid(&self) -> AttributeUuid {
        self.uuid
    }

    /// Returns the GATT characteristic properties
    pub fn properties(&self) -> &CharacteristicProperties {
        &self.properties
    }

    /// Returns the ATT permissions
    pub fn permissions(&self) -> &AttributePermissions {
        &self.permissions
    }
}

/// Wraps logic executed when a value is read from or written to.
pub struct CharacteristicValueHandler {
    pub(crate) read: sync::Arc<Box<dyn AttributeRead>>,
    pub(crate) write: sync::Arc<Box<dyn AttributeWrite>>,
}

impl CharacteristicValueHandler {
    /// Create a new value with the provided read and write callbacks.
    pub fn new(read: Box<dyn AttributeRead>, write: Box<dyn AttributeWrite>) -> Self {
        Self {
            read: sync::Arc::new(read),
            write: sync::Arc::new(write),
        }
    }
}
