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

use bumble::wrapper::PyDictExt;
use pyo3::{intern, prelude::PyModule, types::PyDict, PyAny, PyResult, Python};

mod drivers;
mod hci;
mod transport;

mod att;
mod gatt;

/// Eval the provided snippet.
///
/// The `bumble` module will be available as a global.
fn eval_bumble<'py>(py: Python<'py>, snippet: &str, locals: &'py PyDict) -> PyResult<&'py PyAny> {
    let globals = PyDict::from_pairs(
        py,
        &[("bumble", PyModule::import(py, intern!(py, "bumble"))?)],
    )?;
    // import modules we might use so python doesn't mysteriously fail to access submodules
    // when accessing values that live directly in a module, not in a class in a module
    let _ = PyModule::import(py, intern!(py, "bumble.gatt"))?;

    py.eval(snippet, Some(globals), Some(locals))
}
