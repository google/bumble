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
use pyo3::{
    prelude::*,
    types::{PyDict, PyTuple},
};
pub use pyo3_asyncio;

pub mod assigned_numbers;
pub mod core;
pub mod device;
pub mod gatt_client;
pub mod hci;
pub mod logging;
pub mod profile;
pub mod transport;

/// Convenience extensions to [PyObject]
pub trait PyObjectExt {
    /// Get a GIL-bound reference
    fn gil_ref<'py>(&'py self, py: Python<'py>) -> &'py PyAny;

    /// Extract any [FromPyObject] implementation from this value
    fn extract_with_gil<T>(&self) -> PyResult<T>
    where
        T: for<'a> FromPyObject<'a>,
    {
        Python::with_gil(|py| self.gil_ref(py).extract::<T>())
    }
}

impl PyObjectExt for PyObject {
    fn gil_ref<'py>(&'py self, py: Python<'py>) -> &'py PyAny {
        self.as_ref(py)
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
