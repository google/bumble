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

//! Controller components
use crate::wrapper::{
    common::{TransportSink, TransportSource},
    hci::Address,
    link::Link,
    wrap_python_async, PyDictExt,
};
use pyo3::{
    intern,
    types::{PyDict, PyModule},
    PyObject, PyResult, Python,
};
use pyo3_asyncio::tokio::into_future;

/// A controller that can send and receive HCI frames via some link
#[derive(Clone)]
pub struct Controller(pub(crate) PyObject);

impl Controller {
    /// Creates a new [Controller] object. When optional arguments are not specified, the Python
    /// module specifies the defaults. Must be called from a thread with a Python event loop, which
    /// should be true on `tokio::main` and `async_std::main`.
    ///
    /// For more info, see https://awestlake87.github.io/pyo3-asyncio/master/doc/pyo3_asyncio/#event-loop-references-and-contextvars.
    pub async fn new(
        name: &str,
        host_source: Option<TransportSource>,
        host_sink: Option<TransportSink>,
        link: Option<Link>,
        public_address: Option<Address>,
    ) -> PyResult<Self> {
        Python::with_gil(|py| {
            let controller_ctr = PyModule::import(py, intern!(py, "bumble.controller"))?
                .getattr(intern!(py, "Controller"))?;

            let kwargs = PyDict::new(py);
            kwargs.set_item("name", name)?;
            kwargs.set_opt_item("host_source", host_source)?;
            kwargs.set_opt_item("host_sink", host_sink)?;
            kwargs.set_opt_item("link", link)?;
            kwargs.set_opt_item("public_address", public_address)?;

            // Controller constructor (`__init__`) is not (and can't be) marked async, but calls
            // `get_running_loop`, and thus needs wrapped in an async function.
            wrap_python_async(py, controller_ctr)?
                .call((), Some(kwargs))
                .and_then(into_future)
        })?
        .await
        .map(Self)
    }
}
