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

#[cfg(feature = "unstable_extended_adv")]
use crate::wrapper::{
    hci::packets::{
        self, AdvertisingEventProperties, AdvertisingFilterPolicy, Enable, EnabledSet,
        FragmentPreference, LeSetAdvertisingSetRandomAddressBuilder,
        LeSetExtendedAdvertisingDataBuilder, LeSetExtendedAdvertisingEnableBuilder,
        LeSetExtendedAdvertisingParametersBuilder, Operation, OwnAddressType, PeerAddressType,
        PrimaryPhyType, SecondaryPhyType,
    },
    ConversionError,
};
use crate::{
    adv::AdvertisementDataBuilder,
    wrapper::{
        core::AdvertisingData,
        gatt_client::{ProfileServiceProxy, ServiceProxy},
        hci::{
            packets::{Command, ErrorCode, Event},
            Address, HciCommand, WithPacketType,
        },
        host::Host,
        l2cap::LeConnectionOrientedChannel,
        transport::{Sink, Source},
        ClosureCallback, PyDictExt, PyObjectExt,
    },
};
use pyo3::{
    exceptions::PyException,
    intern,
    types::{PyDict, PyModule},
    IntoPy, PyErr, PyObject, PyResult, Python, ToPyObject,
};
use pyo3_asyncio::tokio::into_future;
use std::path;

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
    obj: PyObject,
    advertising_status: AdvertisingStatus,
}

impl Device {
    #[cfg(feature = "unstable_extended_adv")]
    const ADVERTISING_HANDLE_EXTENDED: u8 = 0x00;

    /// Creates a Device. When optional arguments are not specified, the Python object specifies the
    /// defaults.
    pub fn new(
        name: Option<&str>,
        address: Option<Address>,
        config: Option<DeviceConfiguration>,
        host: Option<Host>,
        generic_access_service: Option<bool>,
    ) -> PyResult<Self> {
        Python::with_gil(|py| {
            let kwargs = PyDict::new(py);
            kwargs.set_opt_item("name", name)?;
            kwargs.set_opt_item("address", address)?;
            kwargs.set_opt_item("config", config)?;
            kwargs.set_opt_item("host", host)?;
            kwargs.set_opt_item("generic_access_service", generic_access_service)?;

            PyModule::import(py, intern!(py, "bumble.device"))?
                .getattr(intern!(py, "Device"))?
                .call((), Some(kwargs))
                .map(|any| Self {
                    obj: any.into(),
                    advertising_status: AdvertisingStatus::NotAdvertising,
                })
        })
    }

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
                .map(|any| Self {
                    obj: any.into(),
                    advertising_status: AdvertisingStatus::NotAdvertising,
                })
        })
    }

    /// Create a Device configured to communicate with a controller through an HCI source/sink
    pub fn with_hci(name: &str, address: Address, source: Source, sink: Sink) -> PyResult<Self> {
        Python::with_gil(|py| {
            PyModule::import(py, intern!(py, "bumble.device"))?
                .getattr(intern!(py, "Device"))?
                .call_method1(intern!(py, "with_hci"), (name, address.0, source.0, sink.0))
                .map(|any| Self {
                    obj: any.into(),
                    advertising_status: AdvertisingStatus::NotAdvertising,
                })
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
    pub async fn connect(&self, peer_addr: &str) -> PyResult<Connection> {
        Python::with_gil(|py| {
            self.obj
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
            callback(py, Advertisement(args.get_item(0)?.into()))
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
        let random_address: packets::Address =
            self.random_address()?.try_into().map_err(|e| match e {
                ConversionError::Python(pyerr) => pyerr,
                ConversionError::Native(e) => PyErr::new::<PyException, _>(format!("{e:?}")),
            })?;
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
                .map(Address)
        })
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

/// Use this address when sending an HCI command that requires providing a peer address, but the
/// command is such that the peer address will be ignored.
///
/// Internal to bumble, this address might mean "any", but a packets::Address typically gets sent
/// directly to a controller, so we don't have to worry about it.
#[cfg(feature = "unstable_extended_adv")]
fn default_ignored_peer_address() -> packets::Address {
    packets::Address::try_from(0x0000_0000_0000_u64).unwrap()
}
