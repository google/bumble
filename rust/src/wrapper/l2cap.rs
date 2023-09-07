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

//! L2CAP

use crate::wrapper::{ClosureCallback, PyObjectExt};
use pyo3::{intern, PyObject, PyResult, Python};

/// L2CAP connection-oriented channel
pub struct LeConnectionOrientedChannel(PyObject);

impl LeConnectionOrientedChannel {
    /// Create a LeConnectionOrientedChannel that wraps the provided obj.
    pub(crate) fn from(obj: PyObject) -> Self {
        Self(obj)
    }

    /// Queues data to be automatically sent across this channel.
    pub fn write(&mut self, data: &[u8]) -> PyResult<()> {
        Python::with_gil(|py| self.0.call_method1(py, intern!(py, "write"), (data,))).map(|_| ())
    }

    /// Wait for queued data to be sent on this channel.
    pub async fn drain(&mut self) -> PyResult<()> {
        Python::with_gil(|py| {
            self.0
                .call_method0(py, intern!(py, "drain"))
                .and_then(|coroutine| pyo3_asyncio::tokio::into_future(coroutine.as_ref(py)))
        })?
        .await
        .map(|_| ())
    }

    /// Register a callback to be called when the channel is closed.
    pub fn on_close(
        &mut self,
        callback: impl Fn(Python) -> PyResult<()> + Send + 'static,
    ) -> PyResult<()> {
        let boxed = ClosureCallback::new(move |py, _args, _kwargs| callback(py));

        Python::with_gil(|py| {
            self.0
                .call_method1(py, intern!(py, "add_listener"), ("close", boxed))
        })
        .map(|_| ())
    }

    /// Register a callback to be called when the channel receives data.
    pub fn set_sink(
        &mut self,
        callback: impl Fn(Python, &[u8]) -> PyResult<()> + Send + 'static,
    ) -> PyResult<()> {
        let boxed = ClosureCallback::new(move |py, args, _kwargs| {
            callback(py, args.get_item(0)?.extract()?)
        });
        Python::with_gil(|py| self.0.setattr(py, intern!(py, "sink"), boxed)).map(|_| ())
    }

    /// Disconnect the l2cap channel.
    /// Must be called from a thread with a Python event loop, which should be true on
    /// `tokio::main` and `async_std::main`.
    ///
    /// For more info, see https://awestlake87.github.io/pyo3-asyncio/master/doc/pyo3_asyncio/#event-loop-references-and-contextvars.
    pub async fn disconnect(&mut self) -> PyResult<()> {
        Python::with_gil(|py| {
            self.0
                .call_method0(py, intern!(py, "disconnect"))
                .and_then(|coroutine| pyo3_asyncio::tokio::into_future(coroutine.as_ref(py)))
        })?
        .await
        .map(|_| ())
    }

    /// Returns some information about the channel as a [String].
    pub fn debug_string(&self) -> PyResult<String> {
        Python::with_gil(|py| {
            let str_obj = self.0.call_method0(py, intern!(py, "__str__"))?;
            str_obj.gil_ref(py).extract()
        })
    }
}
