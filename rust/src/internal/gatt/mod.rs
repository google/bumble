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

//! Core GATT types

use std::ops;
use strum::IntoEnumIterator;

pub(crate) mod server;

/// Combined properties for a GATT characteristic.
/// See [CharacteristicProperty] for individual properties.
///
/// # Examples
///
/// Creating a [CharacteristicProperties] by OR-ing together individual properties:
/// ```
/// use bumble::wrapper::gatt::CharacteristicProperty;
///
/// let mut properties = CharacteristicProperty::Read | CharacteristicProperty::Write;
/// assert!(properties.has_property(CharacteristicProperty::Read));
/// properties |= CharacteristicProperty::Notify;
/// assert!(properties.has_property(CharacteristicProperty::Notify));
/// ```
///
/// Creating a [CharacteristicProperties] directly from an individual property:
/// ```
/// use bumble::wrapper::gatt::{CharacteristicProperties, CharacteristicProperty};
///
/// let properties: CharacteristicProperties = CharacteristicProperty::Broadcast.into();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CharacteristicProperties {
    /// Bit vector of properties `OR`d together.
    ///
    /// See [CharacteristicProperty::as_bit_mask].
    pub(crate) bits: u8,
}

impl CharacteristicProperties {
    /// Returns an iterator over the individual properties set in this instance.
    pub fn iter(&self) -> impl Iterator<Item = CharacteristicProperty> + '_ {
        CharacteristicProperty::iter().filter(|c| self.has_property(*c))
    }

    /// Returns true iff the specified property is set.
    pub fn has_property(&self, p: CharacteristicProperty) -> bool {
        self.bits & p.as_bit_mask() > 0
    }
}

impl From<CharacteristicProperty> for CharacteristicProperties {
    fn from(value: CharacteristicProperty) -> Self {
        Self {
            bits: value.as_bit_mask(),
        }
    }
}

impl ops::BitOr<&Self> for CharacteristicProperties {
    type Output = Self;

    fn bitor(self, rhs: &Self) -> Self::Output {
        Self {
            bits: self.bits | rhs.bits,
        }
    }
}

impl ops::BitOr<CharacteristicProperty> for CharacteristicProperties {
    type Output = Self;

    fn bitor(self, rhs: CharacteristicProperty) -> Self::Output {
        Self {
            bits: self.bits | rhs.as_bit_mask(),
        }
    }
}

impl ops::BitOrAssign<&Self> for CharacteristicProperties {
    fn bitor_assign(&mut self, rhs: &Self) {
        self.bits |= rhs.bits
    }
}

impl ops::BitOrAssign<CharacteristicProperty> for CharacteristicProperties {
    fn bitor_assign(&mut self, rhs: CharacteristicProperty) {
        self.bits |= rhs.as_bit_mask()
    }
}

/// Individual properties defining what operations are permitted for a GATT characteristic value.
/// Combined into [CharacteristicProperties].
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, strum_macros::EnumIter)]
pub enum CharacteristicProperty {
    Broadcast,
    Read,
    WriteWithoutResponse,
    Write,
    Notify,
    Indicate,
    AuthnSignedWrites,
    ExtendedProps,
}

impl CharacteristicProperty {
    /// Returns the assigned bit for the property.
    fn as_bit_mask(&self) -> u8 {
        // Per 3.3.1.1 <https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host/generic-attribute-profile--gatt-.html#UUID-70d11f51-12cd-57a4-184a-fd8a4e0283f9>
        match self {
            CharacteristicProperty::Broadcast => 0x01,
            CharacteristicProperty::Read => 0x02,
            CharacteristicProperty::WriteWithoutResponse => 0x04,
            CharacteristicProperty::Write => 0x08,
            CharacteristicProperty::Notify => 0x10,
            CharacteristicProperty::Indicate => 0x20,
            CharacteristicProperty::AuthnSignedWrites => 0x40,
            CharacteristicProperty::ExtendedProps => 0x80,
        }
    }
}

impl ops::BitOr for CharacteristicProperty {
    type Output = CharacteristicProperties;

    fn bitor(self, rhs: Self) -> Self::Output {
        CharacteristicProperties::from(self) | rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections;

    #[test]
    fn or_into_properties_works() {
        let props = CharacteristicProperty::Indicate | CharacteristicProperty::Read;
        let expected = collections::HashSet::from([
            CharacteristicProperty::Indicate,
            CharacteristicProperty::Read,
        ]);
        assert_eq!(expected, props.iter().collect())
    }
}
