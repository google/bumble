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

//! Bumble & Python logging

use pyo3::types::PyDict;
use pyo3::{intern, types::PyModule, PyResult, Python};
use std::env;

/// Returns the uppercased contents of the `BUMBLE_LOGLEVEL` env var, or `default` if it is not present or not UTF-8.
///
/// The result could be passed to [py_logging_basic_config] to configure Python's logging
/// accordingly.
pub fn bumble_env_logging_level(default: impl Into<String>) -> String {
    env::var("BUMBLE_LOGLEVEL")
        .unwrap_or_else(|_| default.into())
        .to_ascii_uppercase()
}

/// Call `logging.basicConfig` with the provided logging level
pub fn py_logging_basic_config(log_level: impl Into<String>) -> PyResult<()> {
    Python::with_gil(|py| {
        let kwargs = PyDict::new(py);
        kwargs.set_item("level", log_level.into())?;

        PyModule::import(py, intern!(py, "logging"))?
            .call_method(intern!(py, "basicConfig"), (), Some(kwargs))
            .map(|_| ())
    })
}
