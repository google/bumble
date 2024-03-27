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

//! Support for the ATT layer.

pub use crate::internal::att::{
    AttributePermission, AttributePermissions, AttributeRead, AttributeUuid, AttributeWrite,
    MutexRead, NoOpWrite,
};
use crate::wrapper::core::TryToPy;
use pyo3::prelude::PyModule;
use pyo3::types::PyBytes;
use pyo3::{intern, PyAny, PyResult, Python};

impl TryToPy for AttributeUuid {
    fn try_to_py<'py>(&self, py: Python<'py>) -> PyResult<&'py PyAny> {
        let le_bytes = match self {
            AttributeUuid::Uuid16(u) => u.as_le_bytes().to_vec(),
            AttributeUuid::Uuid128(u) => u.as_le_bytes().to_vec(),
        };

        PyModule::import(py, intern!(py, "bumble.core"))?
            .getattr(intern!(py, "UUID"))?
            .getattr(intern!(py, "from_bytes"))?
            .call1((PyBytes::new(py, &le_bytes),))
    }
}

impl TryToPy for AttributePermissions {
    fn try_to_py<'py>(&self, py: Python<'py>) -> PyResult<&'py PyAny> {
        let all_perm_bits = self.iter().fold(0_u8, |accum, perm| {
            accum
                | match perm {
                    // This mapping is what Bumble uses internally; unclear if it's standardized
                    AttributePermission::Readable => 0x01,
                    AttributePermission::Writeable => 0x02,
                    AttributePermission::ReadRequiresEncryption => 0x04,
                    AttributePermission::WriteRequiresEncryption => 0x08,
                    AttributePermission::ReadRequiresAuthn => 0x10,
                    AttributePermission::WriteRequiresAuthn => 0x20,
                    AttributePermission::ReadRequiresAuthz => 0x40,
                    AttributePermission::WriteRequiresAuthz => 0x80,
                }
        });

        PyModule::import(py, intern!(py, "bumble.att"))?
            .getattr(intern!(py, "Attribute"))?
            .getattr(intern!(py, "Permissions"))?
            .call1((all_perm_bits,))
    }
}
