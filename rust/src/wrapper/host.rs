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

//! Host-side types

use crate::wrapper::{
    transport::{Sink, Source},
    wrap_python_async,
};
use pyo3::{intern, prelude::PyModule, types::PyDict, PyObject, PyResult, Python, ToPyObject};
use pyo3_asyncio::tokio::into_future;

/// Host HCI commands
pub struct Host {
    pub(crate) obj: PyObject,
}

impl Host {
    /// Create a Host that wraps the provided obj
    pub(crate) fn from(obj: PyObject) -> Self {
        Self { obj }
    }

    /// Create a new Host
    pub async fn new(source: Source, sink: Sink) -> PyResult<Self> {
        Python::with_gil(|py| {
            let host_ctr =
                PyModule::import(py, intern!(py, "bumble.host"))?.getattr(intern!(py, "Host"))?;

            let kwargs = PyDict::new(py);
            kwargs.set_item("controller_source", source.0)?;
            kwargs.set_item("controller_sink", sink.0)?;

            // Needed for Python 3.8-3.9, in which the Semaphore object, when constructed, calls
            // `get_event_loop`.
            wrap_python_async(py, host_ctr)?
                .call((), Some(kwargs))
                .and_then(into_future)
        })?
        .await
        .map(|any| Self { obj: any })
    }

    /// Send a reset command and perform other reset tasks.
    pub async fn reset(&mut self, driver_factory: DriverFactory) -> PyResult<()> {
        Python::with_gil(|py| {
            let kwargs = match driver_factory {
                DriverFactory::None => {
                    let kw = PyDict::new(py);
                    kw.set_item("driver_factory", py.None())?;
                    Some(kw)
                }
                DriverFactory::Auto => {
                    // leave the default in place
                    None
                }
            };
            self.obj
                .call_method(py, intern!(py, "reset"), (), kwargs)
                .and_then(|coroutine| pyo3_asyncio::tokio::into_future(coroutine.as_ref(py)))
        })?
        .await
        .map(|_| ())
    }
}

impl ToPyObject for Host {
    fn to_object(&self, _py: Python<'_>) -> PyObject {
        self.obj.clone()
    }
}

/// Driver factory to use when initializing a host
#[derive(Debug, Clone)]
pub enum DriverFactory {
    /// Do not load drivers
    None,
    /// Load appropriate driver, if any is found
    Auto,
}
