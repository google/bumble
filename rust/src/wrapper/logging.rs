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
