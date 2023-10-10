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

//! Types that wrap the Python API.
//!
//! Because mutability, aliasing, etc is all hidden behind Python, the normal Rust rules about
//! only one mutable reference to one piece of memory, etc, may not hold since using `&mut self`
//! instead of `&self` is only guided by inspection of the Python source, not the compiler.
//!
//! The modules are generally structured to mirror the Python equivalents.

// Re-exported to make it easy for users to depend on the same `PyObject`, etc
pub use pyo3;
pub use pyo3_asyncio;

use pyo3::{
    intern,
    prelude::*,
    types::{PyDict, PyTuple},
};

pub mod assigned_numbers;
pub mod common;
pub mod controller;
pub mod core;
pub mod device;
pub mod drivers;
pub mod gatt_client;
pub mod hci;
pub mod host;
pub mod l2cap;
pub mod link;
pub mod logging;
pub mod profile;
pub mod transport;

/// Convenience extensions to [PyObject]
pub trait PyObjectExt: Sized {
    /// Get a GIL-bound reference
    fn gil_ref<'py>(&'py self, py: Python<'py>) -> &'py PyAny;

    /// Extract any [FromPyObject] implementation from this value
    fn extract_with_gil<T>(&self) -> PyResult<T>
    where
        T: for<'a> FromPyObject<'a>,
    {
        Python::with_gil(|py| self.gil_ref(py).extract::<T>())
    }

    /// If the Python object is a Python `None`, return a Rust `None`, otherwise `Some` with the mapped type
    fn into_option<T>(self, map_obj: impl Fn(Self) -> T) -> Option<T> {
        Python::with_gil(|py| {
            if self.gil_ref(py).is_none() {
                None
            } else {
                Some(map_obj(self))
            }
        })
    }
}

impl PyObjectExt for PyObject {
    fn gil_ref<'py>(&'py self, py: Python<'py>) -> &'py PyAny {
        self.as_ref(py)
    }
}

/// Convenience extensions to [PyDict]
pub trait PyDictExt {
    /// Set item in dict only if value is Some, otherwise do nothing.
    fn set_opt_item<K: ToPyObject, V: ToPyObject>(&self, key: K, value: Option<V>) -> PyResult<()>;
}

impl PyDictExt for PyDict {
    fn set_opt_item<K: ToPyObject, V: ToPyObject>(&self, key: K, value: Option<V>) -> PyResult<()> {
        if let Some(value) = value {
            self.set_item(key, value)?
        }
        Ok(())
    }
}

/// Wrapper to make Rust closures ([Fn] implementations) callable from Python.
///
/// The Python callable form returns a Python `None`.
#[pyclass(name = "SubscribeCallback")]
pub(crate) struct ClosureCallback {
    // can't use generics in a pyclass, so have to box
    #[allow(clippy::type_complexity)]
    callback: Box<dyn Fn(Python, &PyTuple, Option<&PyDict>) -> PyResult<()> + Send + 'static>,
}

impl ClosureCallback {
    /// Create a new callback around the provided closure
    pub fn new(
        callback: impl Fn(Python, &PyTuple, Option<&PyDict>) -> PyResult<()> + Send + 'static,
    ) -> Self {
        Self {
            callback: Box::new(callback),
        }
    }
}

#[pymethods]
impl ClosureCallback {
    #[pyo3(signature = (*args, **kwargs))]
    fn __call__(
        &self,
        py: Python<'_>,
        args: &PyTuple,
        kwargs: Option<&PyDict>,
    ) -> PyResult<Py<PyAny>> {
        (self.callback)(py, args, kwargs).map(|_| py.None())
    }
}

/// Wraps the Python function in a Python async function. `pyo3_asyncio` needs functions to be
/// marked async to properly inject a running loop.
pub(crate) fn wrap_python_async<'a>(py: Python<'a>, function: &'a PyAny) -> PyResult<&'a PyAny> {
    PyModule::import(py, intern!(py, "bumble.utils"))?
        .getattr(intern!(py, "wrap_async"))?
        .call1((function,))
}

/// Represents the two major kinds of errors that can occur when converting between Rust and Python.
pub enum ConversionError<T> {
    /// Occurs across the Python/native boundary.
    Python(PyErr),
    /// Occurs within the native ecosystem, such as when performing more transformations before
    /// finally converting to the native type.
    Native(T),
}
