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

//! Devices and connections to them

use crate::wrapper::gatt::profile::proxy::ProfileServiceProxy;
#[cfg(doc)]
use crate::wrapper::gatt::server::Characteristic;
#[cfg(feature = "unstable_extended_adv")]
use crate::wrapper::hci::{
    packets::{
        self, AdvertisingEventProperties, AdvertisingFilterPolicy, Enable, EnabledSet,
        FragmentPreference, LeSetAdvertisingSetRandomAddressBuilder,
        LeSetExtendedAdvertisingDataBuilder, LeSetExtendedAdvertisingEnableBuilder,
        LeSetExtendedAdvertisingParametersBuilder, Operation, OwnAddressType, PeerAddressType,
        PrimaryPhyType, SecondaryPhyType,
    },
    AddressConversionError,
};
use crate::wrapper::{
    att::AttributeUuid,
    core::{AdvertisementDataBuilder, AdvertisingData, TryFromPy, TryToPy},
    gatt::{client::ServiceProxy, server::Service},
    hci::{
        packets::{Command, ErrorCode, Event},
        Address, HciCommand, WithPacketType,
    },
    host::Host,
    l2cap::LeConnectionOrientedChannel,
    transport::{Sink, Source},
    wrap_python_async, ClosureCallback, PyDictExt, PyObjectExt,
};
#[cfg(feature = "unstable_extended_adv")]
use anyhow::anyhow;
use pyo3::{
    exceptions::PyException,
    intern,
    types::{PyDict, PyList, PyModule},
    IntoPy, PyAny, PyErr, PyObject, PyResult, Python, ToPyObject,
};
use pyo3_asyncio::tokio::into_future;
use std::{collections, path};

#[cfg(test)]
mod tests;

/// Represents the various properties of some device
pub struct DeviceConfiguration(PyObject);

impl DeviceConfiguration {
    /// Creates a new configuration, letting the internal Python object set all the defaults
    pub fn new() -> PyResult<DeviceConfiguration> {
        Python::with_gil(|py| {
            PyModule::import(py, intern!(py, "bumble.device"))?
                .getattr(intern!(py, "DeviceConfiguration"))?
                .call0()
                .map(|any| Self(any.into()))
        })
    }

    /// Creates a new configuration from the specified file
    pub fn load_from_file(&mut self, device_config: &path::Path) -> PyResult<()> {
        Python::with_gil(|py| {
            self.0
                .call_method1(py, intern!(py, "load_from_file"), (device_config,))
        })
        .map(|_| ())
    }
}

impl ToPyObject for DeviceConfiguration {
    fn to_object(&self, _py: Python<'_>) -> PyObject {
        self.0.clone()
    }
}

/// Used for tracking what advertising state a device might be in
#[derive(PartialEq)]
enum AdvertisingStatus {
    AdvertisingLegacy,
    AdvertisingExtended,
    NotAdvertising,
}

/// A device that can send/receive HCI frames.
pub struct Device {
    /// Python `Device`
    obj: PyObject,
    advertising_status: AdvertisingStatus,
}

impl Device {
    #[cfg(feature = "unstable_extended_adv")]
    const ADVERTISING_HANDLE_EXTENDED: u8 = 0x00;

    /// Creates a Device. When optional arguments are not specified, the Python object specifies the
    /// defaults.
    pub async fn new(
        name: Option<&str>,
        address: Option<Address>,
        config: Option<DeviceConfiguration>,
        host: Option<Host>,
        generic_access_service: Option<bool>,
    ) -> PyResult<Self> {
        Python::with_gil(|py| {
            let kwargs = PyDict::new(py);
            kwargs.set_opt_item("name", name)?;
            kwargs.set_opt_item("address", address.map(|a| a.try_to_py(py)).transpose()?)?;
            kwargs.set_opt_item("config", config)?;
            kwargs.set_opt_item("host", host)?;
            kwargs.set_opt_item("generic_access_service", generic_access_service)?;

            let device_ctor = PyModule::import(py, intern!(py, "bumble.device"))?
                .getattr(intern!(py, "Device"))?;

            // Needed for Python 3.8-3.9, in which the Semaphore object, when constructed, calls
            // `get_event_loop`.
            wrap_python_async(py, device_ctor)?
                .call((), Some(kwargs))
                .and_then(into_future)
        })?
        .await
        .map(|obj| Self {
            obj,
            advertising_status: AdvertisingStatus::NotAdvertising,
        })
    }

    /// Create a Device per the provided file configured to communicate with a controller through an HCI source/sink
    pub async fn from_config_file_with_hci(
        device_config: &path::Path,
        source: Source,
        sink: Sink,
    ) -> PyResult<Self> {
        Python::with_gil(|py| {
            let device_ctor = PyModule::import(py, intern!(py, "bumble.device"))?
                .getattr(intern!(py, "Device"))?
                .getattr(intern!(py, "from_config_file_with_hci"))?;

            // Needed for Python 3.8-3.9, in which the Semaphore object, when constructed, calls
            // `get_event_loop`.
            wrap_python_async(py, device_ctor)?
                .call((device_config, source.0, sink.0), None)
                .and_then(into_future)
        })?
        .await
        .map(|obj| Self {
            obj,
            advertising_status: AdvertisingStatus::NotAdvertising,
        })
    }

    /// Create a Device configured to communicate with a controller through an HCI source/sink
    pub async fn with_hci(
        name: &str,
        address: Address,
        source: Source,
        sink: Sink,
    ) -> PyResult<Self> {
        Python::with_gil(|py| {
            let device_ctor = PyModule::import(py, intern!(py, "bumble.device"))?
                .getattr(intern!(py, "Device"))?
                .getattr(intern!(py, "with_hci"))?;

            // Needed for Python 3.8-3.9, in which the Semaphore object, when constructed, calls
            // `get_event_loop`.
            wrap_python_async(py, device_ctor)?
                .call((name, address.try_to_py(py)?, source.0, sink.0), None)
                .and_then(into_future)
        })?
        .await
        .map(|obj| Self {
            obj,
            advertising_status: AdvertisingStatus::NotAdvertising,
        })
    }

    /// Sends an HCI command on this Device, returning the command's event result.
    ///
    /// When `check_result` is `true`, then an `Err` will be returned if the controller's response
    /// did not have an event code of "success".
    pub async fn send_command(&self, command: Command, check_result: bool) -> PyResult<Event> {
        let bumble_hci_command = HciCommand::try_from(command)?;
        Python::with_gil(|py| {
            self.obj
                .call_method1(
                    py,
                    intern!(py, "send_command"),
                    (bumble_hci_command, check_result),
                )
                .and_then(|coroutine| into_future(coroutine.as_ref(py)))
        })?
        .await
        .and_then(|event| {
            Python::with_gil(|py| {
                let py_bytes = event.call_method0(py, intern!(py, "__bytes__"))?;
                let bytes: &[u8] = py_bytes.extract(py)?;
                let event = Event::parse_with_packet_type(bytes)
                    .map_err(|e| PyErr::new::<PyException, _>(e.to_string()))?;
                Ok(event)
            })
        })
    }

    /// Turn the device on
    pub async fn power_on(&self) -> PyResult<()> {
        Python::with_gil(|py| {
            self.obj
                .call_method0(py, intern!(py, "power_on"))
                .and_then(|coroutine| into_future(coroutine.as_ref(py)))
        })?
        .await
        .map(|_| ())
    }

    /// Connect to a peer
    pub async fn connect(&self, peer_addr: &Address) -> PyResult<Connection> {
        Python::with_gil(|py| {
            self.obj
                .call_method1(py, intern!(py, "connect"), (peer_addr.try_to_py(py)?,))
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
            self.obj
                .call_method1(py, intern!(py, "add_listener"), ("connection", boxed))
        })
        .map(|_| ())
    }

    /// Start scanning
    pub async fn start_scanning(&self, filter_duplicates: bool) -> PyResult<()> {
        Python::with_gil(|py| {
            let kwargs = PyDict::new(py);
            kwargs.set_item("filter_duplicates", filter_duplicates)?;
            self.obj
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
            callback(py, Advertisement::try_from_py(py, args.get_item(0)?)?)
        });

        Python::with_gil(|py| {
            self.obj
                .call_method1(py, intern!(py, "add_listener"), ("advertisement", boxed))
        })
        .map(|_| ())
    }

    /// Set the advertisement data to be used when [Device::start_advertising] is called.
    pub fn set_advertising_data(&mut self, adv_data: AdvertisementDataBuilder) -> PyResult<()> {
        Python::with_gil(|py| {
            self.obj.setattr(
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
            self.obj
                .getattr(py, intern!(py, "host"))
                .map(|obj| obj.into_option(Host::from))
        })
    }

    /// Start advertising the data set with [Device.set_advertisement].
    ///
    /// When `auto_restart` is set to `true`, then the device will automatically restart advertising
    /// when a connected device is disconnected.
    pub async fn start_advertising(&mut self, auto_restart: bool) -> PyResult<()> {
        if self.advertising_status == AdvertisingStatus::AdvertisingExtended {
            return Err(PyErr::new::<PyException, _>("Already advertising in extended mode. Stop the existing extended advertisement to start a legacy advertisement."));
        }
        // Bumble allows (and currently ignores) calling `start_advertising` when already
        // advertising. Because that behavior may change in the future, we continue to delegate the
        // handling to bumble.

        Python::with_gil(|py| {
            let kwargs = PyDict::new(py);
            kwargs.set_item("auto_restart", auto_restart)?;

            self.obj
                .call_method(py, intern!(py, "start_advertising"), (), Some(kwargs))
                .and_then(|coroutine| into_future(coroutine.as_ref(py)))
        })?
        .await
        .map(|_| ())?;

        self.advertising_status = AdvertisingStatus::AdvertisingLegacy;
        Ok(())
    }

    /// Start advertising the data set in extended mode, replacing any existing extended adv. The
    /// advertisement will be non-connectable.
    ///
    /// Fails if the device is already advertising in legacy mode.
    #[cfg(feature = "unstable_extended_adv")]
    pub async fn start_advertising_extended(
        &mut self,
        adv_data: AdvertisementDataBuilder,
    ) -> PyResult<()> {
        // TODO: add tests when local controller object supports extended advertisement commands (github.com/google/bumble/pull/238)
        match self.advertising_status {
            AdvertisingStatus::AdvertisingLegacy => return Err(PyErr::new::<PyException, _>("Already advertising in legacy mode. Stop the existing legacy advertisement to start an extended advertisement.")),
            // Stop the current extended advertisement before advertising with new data.
            // We could just issue an LeSetExtendedAdvertisingData command, but this approach
            // allows better future flexibility if `start_advertising_extended` were to change.
            AdvertisingStatus::AdvertisingExtended => self.stop_advertising_extended().await?,
            _ => {}
        }

        // set extended params
        let properties = AdvertisingEventProperties {
            connectable: 0,
            scannable: 0,
            directed: 0,
            high_duty_cycle: 0,
            legacy: 0,
            anonymous: 0,
            tx_power: 0,
        };
        let extended_advertising_params_cmd = LeSetExtendedAdvertisingParametersBuilder {
            advertising_event_properties: properties,
            advertising_filter_policy: AdvertisingFilterPolicy::AllDevices,
            advertising_handle: Self::ADVERTISING_HANDLE_EXTENDED,
            advertising_sid: 0,
            advertising_tx_power: 0,
            own_address_type: OwnAddressType::RandomDeviceAddress,
            peer_address: default_ignored_peer_address(),
            peer_address_type: PeerAddressType::PublicDeviceOrIdentityAddress,
            primary_advertising_channel_map: 7,
            primary_advertising_interval_max: 200,
            primary_advertising_interval_min: 100,
            primary_advertising_phy: PrimaryPhyType::Le1m,
            scan_request_notification_enable: Enable::Disabled,
            secondary_advertising_max_skip: 0,
            secondary_advertising_phy: SecondaryPhyType::Le1m,
        };
        self.send_command(extended_advertising_params_cmd.into(), true)
            .await?;

        // set random address
        let random_address: packets::Address = self
            .random_address()?
            .try_into()
            .map_err(|e: AddressConversionError| anyhow!(e))?;
        let random_address_cmd = LeSetAdvertisingSetRandomAddressBuilder {
            advertising_handle: Self::ADVERTISING_HANDLE_EXTENDED,
            random_address,
        };
        self.send_command(random_address_cmd.into(), true).await?;

        // set adv data
        let advertising_data_cmd = LeSetExtendedAdvertisingDataBuilder {
            advertising_data: adv_data.into_bytes(),
            advertising_handle: Self::ADVERTISING_HANDLE_EXTENDED,
            fragment_preference: FragmentPreference::ControllerMayFragment,
            operation: Operation::CompleteAdvertisement,
        };
        self.send_command(advertising_data_cmd.into(), true).await?;

        // enable adv
        let extended_advertising_enable_cmd = LeSetExtendedAdvertisingEnableBuilder {
            enable: Enable::Enabled,
            enabled_sets: vec![EnabledSet {
                advertising_handle: Self::ADVERTISING_HANDLE_EXTENDED,
                duration: 0,
                max_extended_advertising_events: 0,
            }],
        };
        self.send_command(extended_advertising_enable_cmd.into(), true)
            .await?;

        self.advertising_status = AdvertisingStatus::AdvertisingExtended;
        Ok(())
    }

    /// Stop advertising.
    pub async fn stop_advertising(&mut self) -> PyResult<()> {
        Python::with_gil(|py| {
            self.obj
                .call_method0(py, intern!(py, "stop_advertising"))
                .and_then(|coroutine| into_future(coroutine.as_ref(py)))
        })?
        .await
        .map(|_| ())?;

        if self.advertising_status == AdvertisingStatus::AdvertisingLegacy {
            self.advertising_status = AdvertisingStatus::NotAdvertising;
        }
        Ok(())
    }

    /// Stop advertising extended.
    #[cfg(feature = "unstable_extended_adv")]
    pub async fn stop_advertising_extended(&mut self) -> PyResult<()> {
        if AdvertisingStatus::AdvertisingExtended != self.advertising_status {
            return Ok(());
        }

        // disable adv
        let extended_advertising_enable_cmd = LeSetExtendedAdvertisingEnableBuilder {
            enable: Enable::Disabled,
            enabled_sets: vec![EnabledSet {
                advertising_handle: Self::ADVERTISING_HANDLE_EXTENDED,
                duration: 0,
                max_extended_advertising_events: 0,
            }],
        };
        self.send_command(extended_advertising_enable_cmd.into(), true)
            .await?;

        self.advertising_status = AdvertisingStatus::NotAdvertising;
        Ok(())
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
            self.obj.call_method(
                py,
                intern!(py, "register_l2cap_channel_server"),
                (),
                Some(kwargs),
            )
        })?;
        Ok(())
    }

    /// Gets the Device's `random_address` property
    pub fn random_address(&self) -> PyResult<Address> {
        Python::with_gil(|py| {
            self.obj
                .getattr(py, intern!(py, "random_address"))
                .and_then(|obj| Address::try_from_py(py, obj.as_ref(py)))
        })
    }

    /// Add a GATT service to the device
    pub fn add_service(&mut self, service: &Service) -> PyResult<ServiceHandle> {
        Python::with_gil(|py| {
            let (char_handles, py_chars): (
                collections::HashMap<AttributeUuid, CharacteristicHandle>,
                Vec<_>,
            ) = service
                .characteristics
                .iter()
                .map(|characteristic| {
                    characteristic.try_to_py(py).map(|py_characteristic| {
                        (
                            (
                                characteristic.uuid,
                                CharacteristicHandle {
                                    uuid: characteristic.uuid,
                                    obj: py_characteristic.into(),
                                },
                            ),
                            py_characteristic,
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .unzip();

            let py_service = PyModule::import(py, intern!(py, "bumble.gatt"))?
                .getattr(intern!(py, "Service"))?
                .call1((service.uuid.try_to_py(py)?, PyList::new(py, py_chars)))?;

            self.obj
                .call_method1(py, intern!(py, "add_service"), (py_service,))
                .map(|_| ServiceHandle {
                    uuid: service.uuid,
                    char_handles,
                })
        })
    }

    /// Notify subscribers to the characteristic
    pub async fn notify_subscribers(&mut self, char_handle: &CharacteristicHandle) -> PyResult<()> {
        Python::with_gil(|py| {
            self.obj
                .call_method1(py, intern!(py, "notify_subscribers"), (&char_handle.obj,))
                .and_then(|coroutine| into_future(coroutine.as_ref(py)))
        })?
        .await
        .map(|_| ())
    }
}

/// A connection to a remote device.
// Wraps a `bumble.device.Connection`
pub struct Connection(pub(crate) PyObject);

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
                .and_then(|coroutine| into_future(coroutine.as_ref(py)))
        })?
        .await
        .map(LeConnectionOrientedChannel::from)
    }

    /// Disconnect from device with provided reason. When optional arguments are not specified, the
    /// Python module specifies the defaults.
    pub async fn disconnect(&mut self, reason: Option<ErrorCode>) -> PyResult<()> {
        Python::with_gil(|py| {
            let kwargs = PyDict::new(py);
            kwargs.set_opt_item("reason", reason)?;
            self.0
                .call_method(py, intern!(py, "disconnect"), (), Some(kwargs))
                .and_then(|coroutine| into_future(coroutine.as_ref(py)))
        })?
        .await
        .map(|_| ())
    }

    /// Register a callback to be called on disconnection.
    pub fn on_disconnection(
        &mut self,
        callback: impl Fn(Python, ErrorCode) -> PyResult<()> + Send + 'static,
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

    /// Returns the address of the peer on the other end of the connection.
    pub fn peer_address(&self) -> PyResult<Address> {
        Python::with_gil(|py| {
            self.0
                .getattr(py, intern!(py, "peer_address"))
                .and_then(|obj| Address::try_from_py(py, obj.as_ref(py)))
        })
    }
}

/// The other end of a connection
pub struct Peer(PyObject);

impl Peer {
    /// Wrap a [Connection] in a Peer
    pub async fn new(conn: Connection) -> PyResult<Self> {
        Python::with_gil(|py| {
            let peer_ctor =
                PyModule::import(py, intern!(py, "bumble.device"))?.getattr(intern!(py, "Peer"))?;

            // Needed for Python 3.8-3.9, in which the Semaphore object, when constructed, calls
            // `get_event_loop`.
            wrap_python_async(py, peer_ctor)?
                .call((conn.0,), None)
                .and_then(into_future)
        })?
        .await
        .map(Self)
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

    /// Populate the peer's cache of characteristics for cached services.
    ///
    /// Should be called after [Peer::discover_services] has cached the available services.
    pub async fn discover_characteristics(&mut self) -> PyResult<()> {
        Python::with_gil(|py| {
            self.0
                .call_method0(py, intern!(py, "discover_characteristics"))
                .and_then(|coroutine| into_future(coroutine.as_ref(py)))
        })?
        .await
        .map(|_| ())
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

    /// Returns the services matching the provided UUID.
    ///
    /// The service cache must have already been populated, e.g. via [Peer::discover_services].
    pub fn services_by_uuid(&self, uuid: impl Into<AttributeUuid>) -> PyResult<Vec<ServiceProxy>> {
        Python::with_gil(|py| {
            self.0
                .call_method1(
                    py,
                    intern!(py, "get_services_by_uuid"),
                    (uuid.into().try_to_py(py)?,),
                )?
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
pub struct Advertisement {
    address: Address,
    connectable: bool,
    rssi: i8,
    data: AdvertisingData,
}

impl Advertisement {
    /// Address that sent the advertisement
    pub fn address(&self) -> Address {
        self.address
    }

    /// Returns true if the advertisement is connectable
    pub fn is_connectable(&self) -> bool {
        self.connectable
    }

    /// RSSI of the advertisement
    pub fn rssi(&self) -> i8 {
        self.rssi
    }

    /// Data in the advertisement
    pub fn data(&self) -> &AdvertisingData {
        &self.data
    }
}

impl TryFromPy for Advertisement {
    fn try_from_py<'py>(py: Python<'py>, obj: &'py PyAny) -> PyResult<Self> {
        Ok(Self {
            address: obj
                .getattr(intern!(py, "address"))
                .and_then(|obj| Address::try_from_py(py, obj))?,
            connectable: obj
                .getattr(intern!(py, "is_connectable"))?
                .extract::<bool>()?,
            rssi: obj.getattr(intern!(py, "rssi"))?.extract::<i8>()?,
            data: obj
                .getattr(intern!(py, "data"))
                .and_then(|obj| AdvertisingData::try_from_py(py, obj))?,
        })
    }
}

/// Use this address when sending an HCI command that requires providing a peer address, but the
/// command is such that the peer address will be ignored.
///
/// Internal to bumble, this address might mean "any", but a packets::Address typically gets sent
/// directly to a controller, so we don't have to worry about it.
#[cfg(feature = "unstable_extended_adv")]
fn default_ignored_peer_address() -> packets::Address {
    packets::Address::try_from(0x0000_0000_0000_u64).unwrap()
}

/// The result of adding a [Service] to a [Device]'s GATT server.
///
/// See [Device::add_service]
///
/// # Background
///
/// Under the hood this is the same Python `Service` type used as an argument to
/// `Device.add_service`, but that relies on `Service` inheriting `Attribute` so that
/// the attribute protocol's handle can be written during `add_service` directly into
/// the `Service` and `Characteristic` objects. The presence of ATT-internal mutable bookkeeping
/// in the higher level `Service` and `Characteristic` doesn't seem very Rust-idiomatic,
/// so the Python `Service` and `Characteristic` produced by [Service] and
/// [Characteristic] during [Device::add_service] are instead exposed
/// as [ServiceHandle] and [CharacteristicHandle], distinct from the higher level
/// [Service] and [Characteristic].
pub struct ServiceHandle {
    uuid: AttributeUuid,
    char_handles: collections::HashMap<AttributeUuid, CharacteristicHandle>,
    // no need for the `Service` PyObject yet, but could certainly be added if needed
}

impl ServiceHandle {
    /// Returns the UUID for the service
    pub fn uuid(&self) -> AttributeUuid {
        self.uuid
    }

    /// Returns the characteristic handle for the characteristic UUID, if it exists.
    pub fn characteristic_handle(
        &self,
        uuid: impl Into<AttributeUuid>,
    ) -> Option<&CharacteristicHandle> {
        self.char_handles.get(&uuid.into())
    }

    /// Returns an iterator over the characteristic handlesin the service.
    pub fn characteristic_handles(&self) -> impl Iterator<Item = &CharacteristicHandle> {
        self.char_handles.values()
    }
}

/// A handle for the result of adding a [Characteristic] as part of a [Service].
///
/// See [Device::add_service] and [ServiceHandle].
pub struct CharacteristicHandle {
    uuid: AttributeUuid,
    /// Python `Characteristic`
    obj: PyObject,
}

impl CharacteristicHandle {
    /// Returns the UUID for the characteristc
    pub fn uuid(&self) -> AttributeUuid {
        self.uuid
    }
}
