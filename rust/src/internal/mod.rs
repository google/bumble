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

//! It's not clear where to put Rust code that isn't simply a wrapper around Python. Until we have
//! a good answer for what to do there, the idea is to put it in this (non-public) module, and
//! `pub use` it into the relevant areas of the `wrapper` module so that it's still easy for users
//! to discover.

pub(crate) mod drivers;
