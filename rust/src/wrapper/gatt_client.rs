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

//! GATT client support

use crate::wrapper::ClosureCallback;
use pyo3::types::PyTuple;
use pyo3::{intern, PyObject, PyResult, Python};

/// A GATT service on a remote device
pub struct ServiceProxy(pub(crate) PyObject);

impl ServiceProxy {
    /// Discover the characteristics in this service.
    ///
    /// Populates an internal cache of characteristics in this service.
    pub async fn discover_characteristics(&mut self) -> PyResult<()> {
        Python::with_gil(|py| {
            self.0
                .call_method0(py, intern!(py, "discover_characteristics"))
                .and_then(|coroutine| pyo3_asyncio::tokio::into_future(coroutine.as_ref(py)))
        })?
        .await
        .map(|_| ())
    }
}

/// A GATT characteristic on a remote device
pub struct CharacteristicProxy(pub(crate) PyObject);

impl CharacteristicProxy {
    /// Subscribe to changes to the characteristic, executing `callback` for each new value
    pub async fn subscribe(
        &mut self,
        callback: impl Fn(Python, &PyTuple) -> PyResult<()> + Send + 'static,
    ) -> PyResult<()> {
        let boxed = ClosureCallback::new(move |py, args, _kwargs| callback(py, args));

        Python::with_gil(|py| {
            self.0
                .call_method1(py, intern!(py, "subscribe"), (boxed,))
                .and_then(|obj| pyo3_asyncio::tokio::into_future(obj.as_ref(py)))
        })?
        .await
        .map(|_| ())
    }

    /// Read the current value of the characteristic
    pub async fn read_value(&self) -> PyResult<PyObject> {
        Python::with_gil(|py| {
            self.0
                .call_method0(py, intern!(py, "read_value"))
                .and_then(|obj| pyo3_asyncio::tokio::into_future(obj.as_ref(py)))
        })?
        .await
    }
}

/// Equivalent to the Python `ProfileServiceProxy`.
pub trait ProfileServiceProxy {
    /// The module containing the proxy class
    const PROXY_CLASS_MODULE: &'static str;
    /// The module class name
    const PROXY_CLASS_NAME: &'static str;

    /// Wrap a PyObject in the Rust wrapper type
    fn wrap(obj: PyObject) -> Self;
}
