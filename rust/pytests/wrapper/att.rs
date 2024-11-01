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

use crate::wrapper::eval_bumble;
use bumble::wrapper::{
    att::{AttributePermission, AttributeUuid},
    core::{TryToPy, Uuid16},
    PyDictExt,
};
use pyo3::{types::PyDict, PyResult, Python};

#[pyo3_asyncio::tokio::test]
fn attribute_permissions_to_py() -> PyResult<()> {
    let perms = AttributePermission::Readable | AttributePermission::Writeable;

    Python::with_gil(|py| {
        let locals = PyDict::from_pairs(py, &[("perms", perms.try_to_py(py)?)])?;

        let and_readable = eval_bumble(
            py,
            "perms & bumble.att.Attribute.Permissions.READABLE",
            locals,
        )?
        .extract::<u8>()?;
        assert_eq!(0x01, and_readable);

        // authz isn't in the set, so should get 0
        let and_read_authz = eval_bumble(
            py,
            "perms & bumble.att.Attribute.Permissions.READ_REQUIRES_AUTHORIZATION",
            locals,
        )?
        .extract::<u8>()?;
        assert_eq!(0, and_read_authz);
        Ok(())
    })
}

#[pyo3_asyncio::tokio::test]
fn attribute_uuid16_to_py() -> PyResult<()> {
    let battery_service = AttributeUuid::Uuid16(Uuid16::from_be_bytes([0x18, 0x0F]));

    Python::with_gil(|py| {
        let locals = PyDict::from_pairs(py, &[("uuid", battery_service.try_to_py(py)?)])?;

        let uuid_str = eval_bumble(py, "uuid.to_hex_str()", locals)?.extract::<String>()?;
        assert_eq!("180F".to_string(), uuid_str);

        let eq_built_in_battery =
            eval_bumble(py, "uuid == bumble.gatt.GATT_BATTERY_SERVICE", locals)?
                .extract::<bool>()?;
        assert!(eq_built_in_battery);

        Ok(())
    })
}

#[pyo3_asyncio::tokio::test]
fn attribute_uuid128_to_py() -> PyResult<()> {
    let expanded_uuid = AttributeUuid::Uuid128(Uuid16::from_be_bytes([0xAA, 0xBB]).into());

    Python::with_gil(|py| {
        let locals = PyDict::from_pairs(py, &[("uuid", expanded_uuid.try_to_py(py)?)])?;

        let uuid_str = eval_bumble(py, "uuid.to_hex_str()", locals)?.extract::<String>()?;
        assert_eq!("0000AABB00001000800000805F9B34FB".to_string(), uuid_str);

        Ok(())
    })
}
