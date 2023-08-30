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

//! Devices and connections to them

use crate::{
    adv::AdvertisementDataBuilder,
    wrapper::{
        core::AdvertisingData,
        gatt_client::{ProfileServiceProxy, ServiceProxy},
        hci::{Address, HciErrorCode},
        host::Host,
        l2cap::LeConnectionOrientedChannel,
        transport::{Sink, Source},
        ClosureCallback, PyDictExt, PyObjectExt,
    },
};
use pyo3::{
    intern,
    types::{PyDict, PyModule},
    IntoPy, PyObject, PyResult, Python, ToPyObject,
};
use pyo3_asyncio::tokio::into_future;
use std::path;

/// A device that can send/receive HCI frames.
#[derive(Clone)]
pub struct Device(PyObject);

impl Device {
    /// Create a Device per the provided file configured to communicate with a controller through an HCI source/sink
    pub fn from_config_file_with_hci(
        device_config: &path::Path,
        source: Source,
        sink: Sink,
    ) -> PyResult<Self> {
        Python::with_gil(|py| {
            PyModule::import(py, intern!(py, "bumble.device"))?
                .getattr(intern!(py, "Device"))?
                .call_method1(
                    intern!(py, "from_config_file_with_hci"),
                    (device_config, source.0, sink.0),
                )
                .map(|any| Self(any.into()))
        })
    }

    /// Create a Device configured to communicate with a controller through an HCI source/sink
    pub fn with_hci(name: &str, address: &str, source: Source, sink: Sink) -> PyResult<Self> {
        Python::with_gil(|py| {
            PyModule::import(py, intern!(py, "bumble.device"))?
                .getattr(intern!(py, "Device"))?
                .call_method1(intern!(py, "with_hci"), (name, address, source.0, sink.0))
                .map(|any| Self(any.into()))
        })
    }

    /// Turn the device on
    pub async fn power_on(&self) -> PyResult<()> {
        Python::with_gil(|py| {
            self.0
                .call_method0(py, intern!(py, "power_on"))
                .and_then(|coroutine| into_future(coroutine.as_ref(py)))
        })?
        .await
        .map(|_| ())
    }

    /// Connect to a peer
    pub async fn connect(&self, peer_addr: &str) -> PyResult<Connection> {
        Python::with_gil(|py| {
            self.0
                .call_method1(py, intern!(py, "connect"), (peer_addr,))
                .and_then(|coroutine| into_future(coroutine.as_ref(py)))
        })?
        .await
        .map(Connection)
    }

    /// Register a callback to be called for each incoming connection.
    pub fn on_connection(
        &mut self,
        callback: impl Fn(Python, Connection) -> PyResult<()> + Send + 'static,
    ) -> PyResult<()> {
        let boxed = ClosureCallback::new(move |py, args, _kwargs| {
            callback(py, Connection(args.get_item(0)?.into()))
        });

        Python::with_gil(|py| {
            self.0
                .call_method1(py, intern!(py, "add_listener"), ("connection", boxed))
        })
        .map(|_| ())
    }

    /// Start scanning
    pub async fn start_scanning(&self, filter_duplicates: bool) -> PyResult<()> {
        Python::with_gil(|py| {
            let kwargs = PyDict::new(py);
            kwargs.set_item("filter_duplicates", filter_duplicates)?;
            self.0
                .call_method(py, intern!(py, "start_scanning"), (), Some(kwargs))
                .and_then(|coroutine| into_future(coroutine.as_ref(py)))
        })?
        .await
        .map(|_| ())
    }

    /// Register a callback to be called for each advertisement
    pub fn on_advertisement(
        &mut self,
        callback: impl Fn(Python, Advertisement) -> PyResult<()> + Send + 'static,
    ) -> PyResult<()> {
        let boxed = ClosureCallback::new(move |py, args, _kwargs| {
            callback(py, Advertisement(args.get_item(0)?.into()))
        });

        Python::with_gil(|py| {
            self.0
                .call_method1(py, intern!(py, "add_listener"), ("advertisement", boxed))
        })
        .map(|_| ())
    }

    /// Set the advertisement data to be used when [Device::start_advertising] is called.
    pub fn set_advertising_data(&mut self, adv_data: AdvertisementDataBuilder) -> PyResult<()> {
        Python::with_gil(|py| {
            self.0.setattr(
                py,
                intern!(py, "advertising_data"),
                adv_data.into_bytes().as_slice(),
            )
        })
        .map(|_| ())
    }

    /// Returns the host used by the device, if any
    pub fn host(&mut self) -> PyResult<Option<Host>> {
        Python::with_gil(|py| {
            self.0
                .getattr(py, intern!(py, "host"))
                .map(|obj| obj.into_option(Host::from))
        })
    }

    /// Start advertising the data set with [Device.set_advertisement].
    pub async fn start_advertising(&mut self, auto_restart: bool) -> PyResult<()> {
        Python::with_gil(|py| {
            let kwargs = PyDict::new(py);
            kwargs.set_item("auto_restart", auto_restart)?;

            self.0
                .call_method(py, intern!(py, "start_advertising"), (), Some(kwargs))
                .and_then(|coroutine| into_future(coroutine.as_ref(py)))
        })?
        .await
        .map(|_| ())
    }

    /// Stop advertising.
    pub async fn stop_advertising(&mut self) -> PyResult<()> {
        Python::with_gil(|py| {
            self.0
                .call_method0(py, intern!(py, "stop_advertising"))
                .and_then(|coroutine| into_future(coroutine.as_ref(py)))
        })?
        .await
        .map(|_| ())
    }

    /// Registers an L2CAP connection oriented channel server. When a client connects to the server,
    /// the `server` callback is passed a handle to the established channel. When optional arguments
    /// are not specified, the Python module specifies the defaults.
    pub fn register_l2cap_channel_server(
        &mut self,
        psm: u16,
        server: impl Fn(Python, LeConnectionOrientedChannel) -> PyResult<()> + Send + 'static,
        max_credits: Option<u16>,
        mtu: Option<u16>,
        mps: Option<u16>,
    ) -> PyResult<()> {
        Python::with_gil(|py| {
            let boxed = ClosureCallback::new(move |py, args, _kwargs| {
                server(
                    py,
                    LeConnectionOrientedChannel::from(args.get_item(0)?.into()),
                )
            });

            let kwargs = PyDict::new(py);
            kwargs.set_item("psm", psm)?;
            kwargs.set_item("server", boxed.into_py(py))?;
            kwargs.set_opt_item("max_credits", max_credits)?;
            kwargs.set_opt_item("mtu", mtu)?;
            kwargs.set_opt_item("mps", mps)?;
            self.0.call_method(
                py,
                intern!(py, "register_l2cap_channel_server"),
                (),
                Some(kwargs),
            )
        })?;
        Ok(())
    }
}

/// A connection to a remote device.
pub struct Connection(PyObject);

impl Connection {
    /// Open an L2CAP channel using this connection. When optional arguments are not specified, the
    /// Python module specifies the defaults.
    pub async fn open_l2cap_channel(
        &mut self,
        psm: u16,
        max_credits: Option<u16>,
        mtu: Option<u16>,
        mps: Option<u16>,
    ) -> PyResult<LeConnectionOrientedChannel> {
        Python::with_gil(|py| {
            let kwargs = PyDict::new(py);
            kwargs.set_item("psm", psm)?;
            kwargs.set_opt_item("max_credits", max_credits)?;
            kwargs.set_opt_item("mtu", mtu)?;
            kwargs.set_opt_item("mps", mps)?;
            self.0
                .call_method(py, intern!(py, "open_l2cap_channel"), (), Some(kwargs))
                .and_then(|coroutine| pyo3_asyncio::tokio::into_future(coroutine.as_ref(py)))
        })?
        .await
        .map(LeConnectionOrientedChannel::from)
    }

    /// Disconnect from device with provided reason. When optional arguments are not specified, the
    /// Python module specifies the defaults.
    pub async fn disconnect(&mut self, reason: Option<HciErrorCode>) -> PyResult<()> {
        Python::with_gil(|py| {
            let kwargs = PyDict::new(py);
            kwargs.set_opt_item("reason", reason)?;
            self.0
                .call_method(py, intern!(py, "disconnect"), (), Some(kwargs))
                .and_then(|coroutine| pyo3_asyncio::tokio::into_future(coroutine.as_ref(py)))
        })?
        .await
        .map(|_| ())
    }

    /// Register a callback to be called on disconnection.
    pub fn on_disconnection(
        &mut self,
        callback: impl Fn(Python, HciErrorCode) -> PyResult<()> + Send + 'static,
    ) -> PyResult<()> {
        let boxed = ClosureCallback::new(move |py, args, _kwargs| {
            callback(py, args.get_item(0)?.extract()?)
        });

        Python::with_gil(|py| {
            self.0
                .call_method1(py, intern!(py, "add_listener"), ("disconnection", boxed))
        })
        .map(|_| ())
    }

    /// Returns some information about the connection as a [String].
    pub fn debug_string(&self) -> PyResult<String> {
        Python::with_gil(|py| {
            let str_obj = self.0.call_method0(py, intern!(py, "__str__"))?;
            str_obj.gil_ref(py).extract()
        })
    }
}

/// The other end of a connection
pub struct Peer(PyObject);

impl Peer {
    /// Wrap a [Connection] in a Peer
    pub fn new(conn: Connection) -> PyResult<Self> {
        Python::with_gil(|py| {
            PyModule::import(py, intern!(py, "bumble.device"))?
                .getattr(intern!(py, "Peer"))?
                .call1((conn.0,))
                .map(|obj| Self(obj.into()))
        })
    }

    /// Populates the peer's cache of services.
    ///
    /// Returns the discovered services.
    pub async fn discover_services(&mut self) -> PyResult<Vec<ServiceProxy>> {
        Python::with_gil(|py| {
            self.0
                .call_method0(py, intern!(py, "discover_services"))
                .and_then(|coroutine| into_future(coroutine.as_ref(py)))
        })?
        .await
        .and_then(|list| {
            Python::with_gil(|py| {
                list.as_ref(py)
                    .iter()?
                    .map(|r| r.map(|h| ServiceProxy(h.to_object(py))))
                    .collect()
            })
        })
    }

    /// Returns a snapshot of the Services currently in the peer's cache
    pub fn services(&self) -> PyResult<Vec<ServiceProxy>> {
        Python::with_gil(|py| {
            self.0
                .getattr(py, intern!(py, "services"))?
                .as_ref(py)
                .iter()?
                .map(|r| r.map(|h| ServiceProxy(h.to_object(py))))
                .collect()
        })
    }

    /// Build a [ProfileServiceProxy] for the specified type.
    /// [Peer::discover_services] or some other means of populating the Peer's service cache must be
    /// called first, or the required service won't be found.
    pub fn create_service_proxy<P: ProfileServiceProxy>(&self) -> PyResult<Option<P>> {
        Python::with_gil(|py| {
            let module = py.import(P::PROXY_CLASS_MODULE)?;
            let class = module.getattr(P::PROXY_CLASS_NAME)?;
            self.0
                .call_method1(py, intern!(py, "create_service_proxy"), (class,))
                .map(|obj| obj.into_option(P::wrap))
        })
    }
}

/// A BLE advertisement
pub struct Advertisement(PyObject);

impl Advertisement {
    /// Address that sent the advertisement
    pub fn address(&self) -> PyResult<Address> {
        Python::with_gil(|py| self.0.getattr(py, intern!(py, "address")).map(Address))
    }

    /// Returns true if the advertisement is connectable
    pub fn is_connectable(&self) -> PyResult<bool> {
        Python::with_gil(|py| {
            self.0
                .getattr(py, intern!(py, "is_connectable"))?
                .extract::<bool>(py)
        })
    }

    /// RSSI of the advertisement
    pub fn rssi(&self) -> PyResult<i8> {
        Python::with_gil(|py| self.0.getattr(py, intern!(py, "rssi"))?.extract::<i8>(py))
    }

    /// Data in the advertisement
    pub fn data(&self) -> PyResult<AdvertisingData> {
        Python::with_gil(|py| self.0.getattr(py, intern!(py, "data")).map(AdvertisingData))
    }
}
