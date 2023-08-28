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

//! Rust API for [Bumble](https://github.com/google/bumble).
//!
//! Bumble is a userspace Bluetooth stack that works with more or less anything that uses HCI. This
//! could be physical Bluetooth USB dongles, netsim, HCI proxied over a network from some device
//! elsewhere, etc.
//!
//! It also does not restrict what you can do with Bluetooth the way that OS Bluetooth APIs
//! typically do, making it good for prototyping, experimentation, test tools, etc.
//!
//! Bumble is primarily written in Python. Rust types that wrap the Python API, which is currently
//! the bulk of the code, are in the [wrapper] module.

#![deny(missing_docs, unsafe_code)]

pub mod wrapper;

pub mod adv;

pub(crate) mod internal;
