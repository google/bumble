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

use bumble::wrapper::{self, core::Uuid16};
use pyo3::{intern, prelude::*, types::PyDict};
use std::collections;

#[pyo3_asyncio::tokio::test]
async fn company_ids_matches_python() -> PyResult<()> {
    let ids_from_python = Python::with_gil(|py| {
        PyModule::import(py, intern!(py, "bumble.company_ids"))?
            .getattr(intern!(py, "COMPANY_IDENTIFIERS"))?
            .downcast::<PyDict>()?
            .into_iter()
            .map(|(k, v)| {
                Ok((
                    Uuid16::from_be_bytes(k.extract::<u16>()?.to_be_bytes()),
                    v.str()?.to_str()?.to_string(),
                ))
            })
            .collect::<PyResult<collections::HashMap<_, _>>>()
    })?;

    assert_eq!(
        wrapper::assigned_numbers::COMPANY_IDS
            .iter()
            .map(|(id, name)| (*id, name.to_string()))
            .collect::<collections::HashMap<_, _>>(),
        ids_from_python,
        "Company ids do not match -- re-run gen_assigned_numbers?"
    );
    Ok(())
}
