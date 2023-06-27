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

use pyo3::PyObject;

/// Equivalent to the Python `ProfileServiceProxy`.
pub trait ProfileServiceProxy {
    /// The module containing the proxy class
    const PROXY_CLASS_MODULE: &'static str;
    /// The module class name
    const PROXY_CLASS_NAME: &'static str;

    /// Wrap a PyObject in the Rust wrapper type
    fn wrap(obj: PyObject) -> Self;
}
