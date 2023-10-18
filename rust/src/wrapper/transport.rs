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

//! HCI packet transport

use crate::wrapper::controller::Controller;
use futures::executor::block_on;
use pyo3::{intern, types::PyModule, PyObject, PyResult, Python};

/// A source/sink pair for HCI packet I/O.
///
/// See <https://google.github.io/bumble/transports/index.html>.
pub struct Transport(PyObject);

impl Transport {
    /// Open a new Transport for the provided spec, e.g. `"usb:0"` or `"android-netsim"`.
    pub async fn open(transport_spec: impl Into<String>) -> PyResult<Self> {
        Python::with_gil(|py| {
            PyModule::import(py, intern!(py, "bumble.transport"))?
                .call_method1(intern!(py, "open_transport"), (transport_spec.into(),))
                .and_then(pyo3_asyncio::tokio::into_future)
        })?
        .await
        .map(Self)
    }

    /// Close the transport.
    pub async fn close(&mut self) -> PyResult<()> {
        Python::with_gil(|py| {
            self.0
                .call_method0(py, intern!(py, "close"))
                .and_then(|coroutine| pyo3_asyncio::tokio::into_future(coroutine.as_ref(py)))
        })?
        .await
        .map(|_| ())
    }

    /// Returns the source half of the transport.
    pub fn source(&self) -> PyResult<Source> {
        Python::with_gil(|py| self.0.getattr(py, intern!(py, "source"))).map(Source)
    }

    /// Returns the sink half of the transport.
    pub fn sink(&self) -> PyResult<Sink> {
        Python::with_gil(|py| self.0.getattr(py, intern!(py, "sink"))).map(Sink)
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        // don't spawn a thread to handle closing, as it may get dropped at program termination,
        // resulting in `RuntimeWarning: coroutine ... was never awaited` from Python
        let _ = block_on(self.close());
    }
}

/// The source side of a [Transport].
#[derive(Clone)]
pub struct Source(pub(crate) PyObject);

impl From<Controller> for Source {
    fn from(value: Controller) -> Self {
        Self(value.0)
    }
}

/// The sink side of a [Transport].
#[derive(Clone)]
pub struct Sink(pub(crate) PyObject);

impl From<Controller> for Sink {
    fn from(value: Controller) -> Self {
        Self(value.0)
    }
}
