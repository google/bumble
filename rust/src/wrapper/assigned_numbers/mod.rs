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

//! Assigned numbers from the Bluetooth spec.

use crate::wrapper::core::Uuid16;
use lazy_static::lazy_static;
use pyo3::{
    intern,
    types::{PyDict, PyModule},
    PyResult, Python,
};
use std::collections;

mod services;

pub use services::SERVICE_IDS;

lazy_static! {
    /// Assigned company IDs
    pub static ref COMPANY_IDS: collections::HashMap<Uuid16, String> = load_company_ids()
    .expect("Could not load company ids -- are Bumble's Python sources available?");

}

fn load_company_ids() -> PyResult<collections::HashMap<Uuid16, String>> {
    // this takes about 4ms on a fast machine -- slower than constructing in rust, but not slow
    // enough to worry about
    Python::with_gil(|py| {
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
    })
}
