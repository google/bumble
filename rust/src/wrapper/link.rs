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

//! Link components
use pyo3::{intern, types::PyModule, PyObject, PyResult, Python, ToPyObject};

/// Link bus for controllers to communicate with each other
#[derive(Clone)]
pub struct Link(pub(crate) PyObject);

impl Link {
    /// Creates a [Link] object that transports messages locally
    pub fn new_local_link() -> PyResult<Self> {
        Python::with_gil(|py| {
            PyModule::import(py, intern!(py, "bumble.link"))?
                .getattr(intern!(py, "LocalLink"))?
                .call0()
                .map(|any| Self(any.into()))
        })
    }
}

impl ToPyObject for Link {
    fn to_object(&self, _py: Python<'_>) -> PyObject {
        self.0.clone()
    }
}
