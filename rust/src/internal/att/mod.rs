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

//! Core types for the ATT layer

use crate::internal::core::{Uuid128, Uuid16};
use crate::wrapper::device::Connection;
use async_trait::async_trait;
use std::ops::Deref;
use std::{collections, ops, sync};

/// One or more [AttributePermission].
///
/// # Examples
/// ```
/// use bumble::wrapper::att::{AttributePermission, AttributePermissions};
///
/// let perms: AttributePermissions =
///     AttributePermission::Readable | AttributePermission::Writeable;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributePermissions {
    permissions: collections::HashSet<AttributePermission>,
}

impl AttributePermissions {
    /// Returns an iterator over the [AttributePermission] set in this instance.
    pub fn iter(&self) -> impl Iterator<Item = AttributePermission> + '_ {
        self.permissions.iter().copied()
    }

    /// Returns true iff `permission` is set.
    pub fn has_permission(&self, permission: AttributePermission) -> bool {
        self.permissions.contains(&permission)
    }
}

impl From<AttributePermission> for AttributePermissions {
    fn from(value: AttributePermission) -> Self {
        Self {
            permissions: collections::HashSet::from([value]),
        }
    }
}

impl ops::BitOr<&Self> for AttributePermissions {
    type Output = Self;

    fn bitor(mut self, rhs: &Self) -> Self::Output {
        self.permissions.extend(rhs.permissions.iter());
        self
    }
}

impl ops::BitOr<AttributePermission> for AttributePermissions {
    type Output = Self;

    fn bitor(mut self, rhs: AttributePermission) -> Self::Output {
        self.permissions.insert(rhs);
        self
    }
}

impl ops::BitOrAssign<&Self> for AttributePermissions {
    fn bitor_assign(&mut self, rhs: &Self) {
        self.permissions.extend(rhs.permissions.iter());
    }
}

impl ops::BitOrAssign<AttributePermission> for AttributePermissions {
    fn bitor_assign(&mut self, rhs: AttributePermission) {
        self.permissions.insert(rhs);
    }
}

/// An individual attribute permission
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttributePermission {
    Readable,
    Writeable,
    ReadRequiresEncryption,
    WriteRequiresEncryption,
    ReadRequiresAuthn,
    WriteRequiresAuthn,
    ReadRequiresAuthz,
    WriteRequiresAuthz,
}

impl ops::BitOr for AttributePermission {
    type Output = AttributePermissions;

    fn bitor(self, rhs: Self) -> Self::Output {
        AttributePermissions {
            permissions: collections::HashSet::from([self, rhs]),
        }
    }
}

/// A UUID that defines a particular attribute's type.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum AttributeUuid {
    /// 16-bit UUID, limited to types in the BLE spec
    Uuid16(Uuid16),
    /// 128-bit UUID, for custom entities
    Uuid128(Uuid128),
}

impl From<Uuid16> for AttributeUuid {
    fn from(value: Uuid16) -> Self {
        Self::Uuid16(value)
    }
}

impl From<Uuid128> for AttributeUuid {
    fn from(value: Uuid128) -> Self {
        Self::Uuid128(value)
    }
}

/// Callback invoked when a GATT client reads an attribute value
#[async_trait]
pub trait AttributeRead: Send + Sync {
    /// Produce data to send to the client at `conn`.
    ///
    /// Takes `&self`, not `&mut self`, to allow concurrent invocations.
    async fn read(&self, conn: Connection) -> anyhow::Result<Vec<u8>>;
}

/// Callback invoked when a GATT client writes an attribute value
#[async_trait]
pub trait AttributeWrite: Send + Sync {
    /// Accept data provided by the client at `conn`.
    ///
    /// Takes `&self`, not `&mut self`, to allow concurrent invocations.
    async fn write(&self, data: Vec<u8>, conn: Connection) -> anyhow::Result<()>;
}

/// An [AttributeWrite] impl that does nothing when invoked.
pub struct NoOpWrite;

#[async_trait]
impl AttributeWrite for NoOpWrite {
    async fn write(&self, _data: Vec<u8>, _conn: Connection) -> anyhow::Result<()> {
        // no op
        Ok(())
    }
}

// For user convenience, impl read/write for Arc'd handlers
#[async_trait]
impl<T: AttributeRead> AttributeRead for sync::Arc<T> {
    async fn read(&self, conn: Connection) -> anyhow::Result<Vec<u8>> {
        self.deref().read(conn).await
    }
}

#[async_trait]
impl<T: AttributeWrite> AttributeWrite for sync::Arc<T> {
    async fn write(&self, data: Vec<u8>, conn: Connection) -> anyhow::Result<()> {
        self.deref().write(data, conn).await
    }
}

/// A simple [AttributeRead] that just holds bytes wrapped in a mutex for convenient changing
/// on the fly
pub struct MutexRead {
    data: sync::Mutex<Vec<u8>>,
}

impl MutexRead {
    /// Create a new MutexRead with the provided `data`
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data: sync::Mutex::new(data),
        }
    }

    /// Set a new value to be used on the next read
    pub fn set(&self, data: &[u8]) {
        let mut guard = self.data.lock().unwrap();
        guard.clear();
        guard.extend_from_slice(data);
    }
}

#[async_trait]
impl AttributeRead for MutexRead {
    async fn read(&self, _conn: Connection) -> anyhow::Result<Vec<u8>> {
        Ok(self.data.lock().unwrap().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn or_into_perms_works() {
        let perms = AttributePermission::Readable | AttributePermission::Writeable;

        let expected = collections::HashSet::from([
            AttributePermission::Readable,
            AttributePermission::Writeable,
        ]);

        assert_eq!(expected, perms.iter().collect());
    }
}
