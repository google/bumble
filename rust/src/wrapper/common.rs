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

//! Shared resources found under bumble's common.py
use pyo3::{PyObject, Python, ToPyObject};

/// Represents the sink for some transport mechanism
pub struct TransportSink(pub(crate) PyObject);

impl ToPyObject for TransportSink {
    fn to_object(&self, _py: Python<'_>) -> PyObject {
        self.0.clone()
    }
}

/// Represents the source for some transport mechanism
pub struct TransportSource(pub(crate) PyObject);

impl ToPyObject for TransportSource {
    fn to_object(&self, _py: Python<'_>) -> PyObject {
        self.0.clone()
    }
}
