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

//! GATT client support

use crate::wrapper::att::AttributeUuid;
use crate::wrapper::core::TryToPy;
#[cfg(doc)]
use crate::wrapper::device::Peer;
use crate::wrapper::ClosureCallback;
use anyhow::anyhow;
use log::warn;
use pyo3::types::PyInt;
#[cfg(doc)]
use pyo3::PyAny;
use pyo3::{intern, types::PyBytes, PyObject, PyResult, PyTryFrom, Python, ToPyObject};
use std::marker;

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

    /// Return the characteristics matching the provided UUID.
    pub fn characteristics_by_uuid(
        &self,
        uuid: impl Into<AttributeUuid>,
    ) -> PyResult<Vec<CharacteristicProxy<Vec<u8>>>> {
        Python::with_gil(|py| {
            self.0
                .call_method1(
                    py,
                    intern!(py, "get_characteristics_by_uuid"),
                    (uuid.into().try_to_py(py)?,),
                )?
                .as_ref(py)
                .iter()?
                .map(|r| r.map(|h| CharacteristicProxy::new(h.to_object(py))))
                .collect()
        })
    }
}

/// A GATT characteristic on a remote device that converts values from the Python side with `V`.
///
/// `V` must be selected appropriately for the underlying Python representation of the
/// characteristic value. See the [CharacteristicBaseValue] docs.
pub struct CharacteristicProxy<V: CharacteristicBaseValue> {
    obj: PyObject,
    value_marker: marker::PhantomData<V>,
}

impl<V: CharacteristicBaseValue> CharacteristicProxy<V> {
    /// Create a new proxy around a Python `Characteristic`
    pub(crate) fn new(obj: PyObject) -> Self {
        Self {
            obj,
            value_marker: Default::default(),
        }
    }

    /// Read the current value of the characteristic
    pub async fn read_value(&self) -> PyResult<V> {
        Python::with_gil(|py| {
            self.obj
                .call_method0(py, intern!(py, "read_value"))
                .and_then(|obj| pyo3_asyncio::tokio::into_future(obj.as_ref(py)))
        })?
        .await
        .and_then(|obj| {
            Python::with_gil(|py| {
                obj.downcast::<V::PythonType>(py)
                    .map_err(|e| e.into())
                    .and_then(V::from_python)
            })
        })
    }

    /// Subscribe to changes to the characteristic, executing `callback` for each new value
    pub async fn subscribe(&mut self, callback: impl Fn(V) + Send + 'static) -> PyResult<()> {
        let boxed = ClosureCallback::new(move |_py, args, _kwargs| {
            args.get_item(0)
                .and_then(|obj| obj.downcast::<V::PythonType>().map_err(|e| e.into()))
                .and_then(V::from_python)
                .map(&callback)
        });

        Python::with_gil(|py| {
            self.obj
                .call_method1(py, intern!(py, "subscribe"), (boxed,))
                .and_then(|obj| pyo3_asyncio::tokio::into_future(obj.as_ref(py)))
        })?
        .await
        .map(|_| ())
    }
}

/// Abstracts over the different ways that Python Bumble represents characteristic values.
///
/// If a characteristic is accessed directly from a [Peer], the underlying representation is a
/// Python `bytes`, and Rust `Vec<u8>` is suitable via [PyBytes].
///
/// If it's accessed via a `CharacteristicAdapter`, however (e.g. via a `ProfileServiceProxy`),
/// the Python representation depends on the adapter used. A Python `int`, for instance, would
/// require a Rust numeric type like `u8` via [PyInt].
pub trait CharacteristicBaseValue: Sized + Send {
    /// Py03 type to `downcast()` [PyAny] to
    type PythonType: for<'a> PyTryFrom<'a>;

    /// Extract `Self` from the downcasted type
    fn from_python(py_obj: &Self::PythonType) -> PyResult<Self>;
}

impl CharacteristicBaseValue for Vec<u8> {
    type PythonType = PyBytes;

    fn from_python(py_obj: &Self::PythonType) -> PyResult<Self> {
        Ok(py_obj.as_bytes().to_vec())
    }
}

impl CharacteristicBaseValue for u8 {
    type PythonType = PyInt;

    fn from_python(py_obj: &Self::PythonType) -> PyResult<Self> {
        py_obj.extract()
    }
}

/// A wrapper around a [CharacteristicProxy] for converting to the characteristic value to a
/// more convenient type.
pub struct CharacteristicAdapter<V, A>
where
    V: CharacteristicBaseValue,
    A: CharacteristicAdaptedValue<V>,
{
    proxy: CharacteristicProxy<V>,
    adapted_marker: marker::PhantomData<A>,
}

impl<V, A> CharacteristicAdapter<V, A>
where
    V: CharacteristicBaseValue,
    A: CharacteristicAdaptedValue<V>,
{
    /// Create a new adapter wrapping `proxy`
    pub fn new(proxy: CharacteristicProxy<V>) -> Self {
        Self {
            proxy,
            adapted_marker: Default::default(),
        }
    }

    /// Read the value from the characteristic, deserialized into `A`.
    pub async fn read_value(&self) -> PyResult<A> {
        self.proxy
            .read_value()
            .await
            .and_then(|value| A::deserialize(value).map_err(|e| anyhow!(e).into()))
    }

    /// Subscribe to notifications, deserializing each value to `C` before invoking the callback.
    ///
    /// If deserialization fails, the error will be logged at `warn`.
    pub async fn subscribe(&mut self, callback: impl Fn(A) + Send + 'static) -> PyResult<()> {
        self.proxy
            .subscribe(move |base_value| match A::deserialize(base_value) {
                Ok(v) => callback(v),
                Err(e) => {
                    warn!("Could not deserialize value: {}", e)
                }
            })
            .await
    }
}

/// Provides characteristic value conversions for a specific higher level type.
///
/// `V` defines the [CharacteristicBaseValue] on top of which the conversion can be applied.
pub trait CharacteristicAdaptedValue<V>: Sized + Send {
    /// Deserialize [Self] from a characteristic value's bytes
    fn deserialize(base_value: V) -> Result<Self, CharacteristicValueDeserializationError>;
    /// Serialize [Self] into bytes to write into a characteristic
    fn serialize(value: Self) -> V;
}

/// Error used when [CharacteristicAdaptedValue] fails
#[derive(thiserror::Error, Debug)]
#[error("Value deserialization failed: {0}")]
pub struct CharacteristicValueDeserializationError(anyhow::Error);

impl CharacteristicAdaptedValue<Vec<u8>> for u8 {
    fn deserialize(base_value: Vec<u8>) -> Result<Self, CharacteristicValueDeserializationError> {
        base_value
            .first()
            .copied()
            .ok_or_else(|| CharacteristicValueDeserializationError(anyhow!("Empty value")))
    }

    fn serialize(value: Self) -> Vec<u8> {
        vec![value]
    }
}
