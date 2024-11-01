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

//! GATT services

use crate::internal::att::AttributeWrite;
pub use crate::internal::gatt::server::{Characteristic, CharacteristicValueHandler, Service};
use crate::wrapper::att::AttributeRead;
use crate::wrapper::core::TryToPy;
use crate::wrapper::device::Connection;
use pyo3::exceptions::PyException;
use pyo3::prelude::PyModule;
use pyo3::types::{PyBytes, PyDict, PyTuple};
use pyo3::{intern, pyclass, pymethods, Py, PyAny, PyErr, PyObject, PyResult, Python};
use std::sync;

impl TryToPy for Characteristic {
    fn try_to_py<'py>(&self, py: Python<'py>) -> PyResult<&'py PyAny> {
        PyModule::import(py, intern!(py, "bumble.gatt"))?
            .getattr(intern!(py, "Characteristic"))?
            .call1((
                self.uuid.try_to_py(py)?,
                self.properties.try_to_py(py)?,
                self.permissions.try_to_py(py)?,
                self.value.try_to_py(py)?,
            ))
    }
}

impl TryToPy for CharacteristicValueHandler {
    fn try_to_py<'py>(&self, py: Python<'py>) -> PyResult<&'py PyAny> {
        PyModule::import(py, intern!(py, "bumble.gatt"))?
            .getattr(intern!(py, "CharacteristicValue"))?
            .call1((
                AttributeReadWrapper {
                    read: self.read.clone(),
                },
                AttributeWriteWrapper {
                    write: self.write.clone(),
                },
            ))
    }
}

/// Python callable used to wrap the attribute read callback
#[pyclass(module = "bumble.rust")]
struct AttributeReadWrapper {
    read: sync::Arc<Box<dyn AttributeRead>>,
}

#[pymethods]
impl AttributeReadWrapper {
    #[allow(unused)]
    // Without `signature`, python tries to squeeze the first arg (Connection) into PyTuple
    // and of course fails.
    #[pyo3(signature = (* args, * * kwargs))]
    fn __call__(
        &self,
        py: Python<'_>,
        args: &PyTuple,
        kwargs: Option<&PyDict>,
    ) -> PyResult<PyObject> {
        let callback = self.read.clone();
        let conn = args
            .iter()
            .next()
            .ok_or_else(|| PyErr::new::<PyException, _>("Could not get connection"))
            .map(|any| Connection(any.into()))?;

        pyo3_asyncio::tokio::future_into_py(py, async move {
            callback
                .read(conn)
                .await
                // acquire GIL later, after waiting, then wrap in Py to decouple from that short GIL
                .map(|v| Python::with_gil(|py2| Py::<PyBytes>::from(PyBytes::new(py2, &v))))
                .map_err(|e| e.into())
        })
        // Between the two GILs and Futures, the lifetimes are confusing, but the compiler agrees
        // that decoupling the &PyAny that holds the future from py's lifetime here is ok
        .map(|py_any| py_any.into())
    }
}

/// Like [AttributeReadWrapper] but for attribute writes
#[pyclass(module = "bumble.rust")]
struct AttributeWriteWrapper {
    write: sync::Arc<Box<dyn AttributeWrite>>,
}

#[pymethods]
impl AttributeWriteWrapper {
    #[allow(unused)]
    #[pyo3(signature = (* args, * * kwargs))]
    fn __call__(
        &self,
        py: Python<'_>,
        args: &PyTuple,
        kwargs: Option<&PyDict>,
    ) -> PyResult<PyObject> {
        let bytes = args
            .iter()
            .nth(1)
            .ok_or(PyErr::new::<PyException, _>(
                "No bytes provided to write callback",
            ))?
            .downcast::<PyBytes>()?
            .as_bytes()
            .to_vec();
        let conn = args
            .iter()
            .next()
            .ok_or_else(|| PyErr::new::<PyException, _>("Could not get connection"))
            .map(|any| Connection(any.into()))?;

        let callback = self.write.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            callback
                .write(bytes, conn)
                .await
                .map(|_| Python::with_gil(|py2| py2.None()))
                .map_err(|_| PyErr::new::<PyException, _>("Attribute read failed"))
        })
        .map(|py_any| py_any.into())
    }
}
