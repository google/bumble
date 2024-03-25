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

use crate::rootcanal::run_with_rootcanal;
use crate::wrapper::eval_bumble;
use anyhow::anyhow;
use bumble::wrapper::gatt::client::CharacteristicProxy;
use bumble::{
    adv::{AdvertisementDataBuilder, CommonDataType},
    wrapper::{
        att::{AttributePermission, MutexRead, NoOpWrite},
        core::{TryToPy, Uuid128},
        device::{Device, Peer, ServiceHandle},
        gatt::{
            server::{Characteristic, CharacteristicValueHandler, Service},
            CharacteristicProperty,
        },
        hci::{packets::AddressType, Address},
        transport::Transport,
        PyDictExt,
    },
};
use pyo3::{types::PyDict, PyResult, Python};
use std::sync::Arc;

#[pyo3_asyncio::tokio::test]
fn characteristic_properties_to_py() -> PyResult<()> {
    let props = CharacteristicProperty::Read | CharacteristicProperty::Write;

    Python::with_gil(|py| {
        let locals = PyDict::from_pairs(py, &[("props", props.try_to_py(py)?)])?;

        let and_read = eval_bumble(
            py,
            "props & bumble.gatt.Characteristic.Properties.READ",
            locals,
        )?
        .extract::<u8>()?;
        assert_eq!(0x02, and_read);

        // notify not in the set, should get 0
        let and_notify = eval_bumble(
            py,
            "props & bumble.gatt.Characteristic.Properties.NOTIFY",
            locals,
        )?
        .extract::<u8>()?;
        assert_eq!(0, and_notify);
        Ok(())
    })
}

#[pyo3_asyncio::tokio::test]
async fn rootcanal_gatt_client_connects_to_service_and_reads() -> PyResult<()> {
    run_with_rootcanal(|rc_ports| async move {
        let transport_spec = format!("tcp-client:127.0.0.1:{}", rc_ports.hci_port);

        // random (type 4) UUIDs
        let service_uuid = Uuid128::parse_str("074e27b7-cd51-4678-b74a-09fdc8f363fc").unwrap();
        let characteristic_uuid =
            Uuid128::parse_str("5666aaef-cd71-47d5-9ad3-c81a72c1521f").unwrap();

        let initial_characteristic_value = vec![1, 2, 3, 4];
        let (server_address, _server_transport, _server_device, read_handler, _service_handle) =
            start_server(
                &transport_spec,
                service_uuid,
                characteristic_uuid,
                initial_characteristic_value.clone(),
            )
            .await?;

        let (_client_transport, discovered_characteristic) = connect_and_discover(
            transport_spec,
            service_uuid,
            characteristic_uuid,
            &server_address,
        )
        .await?;

        // read the value
        assert_eq!(
            initial_characteristic_value,
            discovered_characteristic.read_value().await?
        );

        // update the server for the second read
        read_handler.set(&[5, 6, 7, 8]);

        // read again
        assert_eq!(
            vec![5, 6, 7, 8],
            discovered_characteristic.read_value().await?
        );

        Ok(())
    })
    .await
    .map_err(|e| e.into())
}

#[pyo3_asyncio::tokio::test]
async fn rootcanal_gatt_client_connects_to_service_and_is_notified() -> PyResult<()> {
    run_with_rootcanal(|rc_ports| async move {
        let transport_spec = format!("tcp-client:127.0.0.1:{}", rc_ports.hci_port);

        // random (type 4) UUIDs
        let service_uuid = Uuid128::parse_str("074e27b7-cd51-4678-b74a-09fdc8f363fc").unwrap();
        let characteristic_uuid =
            Uuid128::parse_str("5666aaef-cd71-47d5-9ad3-c81a72c1521f").unwrap();

        let initial_characteristic_value = vec![1, 2, 3, 4];
        let (server_address, _server_transport, mut server_device, _read_handler, service_handle) =
            start_server(
                &transport_spec,
                service_uuid,
                characteristic_uuid,
                initial_characteristic_value.clone(),
            )
            .await?;

        let (_client_transport, mut discovered_characteristic) = connect_and_discover(
            transport_spec,
            service_uuid,
            characteristic_uuid,
            &server_address,
        )
        .await?;

        let char_handle = service_handle
            .characteristic_handle(characteristic_uuid)
            .ok_or(anyhow!("Characteristic not found"))?;

        // using a broadcast channel so we don't have to deal with a blocking or async send
        let (tx, mut rx) = tokio::sync::broadcast::channel(1);

        // notify the client
        discovered_characteristic
            .subscribe(move |value| {
                let clone = tx.clone();
                let _ = clone.send(value);
            })
            .await?;

        server_device.notify_subscribers(char_handle).await?;

        let notify_data = rx.recv().await?;
        assert_eq!(initial_characteristic_value, notify_data);

        Ok(())
    })
    .await
    .map_err(|e| e.into())
}

/// Start a GATT server with the specified characteristic
///
/// Returns transport to keep it alive for the duration of the test
async fn start_server(
    transport_spec: &str,
    service_uuid: Uuid128,
    characteristic_uuid: Uuid128,
    initial_characteristic_value: Vec<u8>,
) -> anyhow::Result<(Address, Transport, Device, Arc<MutexRead>, ServiceHandle)> {
    // start server
    let server_transport = Transport::open(transport_spec).await?;
    let server_address =
        Address::from_be_hex("F0:F1:F2:F3:F4:F5", AddressType::RandomDeviceAddress)
            .map_err(|e| anyhow!(e))?;
    let mut server_device = Device::with_hci(
        "Bumble",
        server_address,
        server_transport.source()?,
        server_transport.sink()?,
    )
    .await?;
    server_device.power_on().await?;

    // add service
    let read_handler = Arc::new(MutexRead::new(initial_characteristic_value));
    let characteristic = Characteristic::new(
        characteristic_uuid.into(),
        CharacteristicProperty::Read | CharacteristicProperty::Notify,
        AttributePermission::Readable.into(),
        CharacteristicValueHandler::new(Box::new(read_handler.clone()), Box::new(NoOpWrite)),
    );
    let service = Service::new(service_uuid.into(), vec![characteristic]);
    let service_handle = server_device.add_service(&service)?;

    // broadcast adv for service
    let mut builder = AdvertisementDataBuilder::new();
    builder.append(CommonDataType::CompleteLocalName, "Bumble Test")?;
    builder.append(
        CommonDataType::IncompleteListOf128BitServiceClassUuids,
        &service_uuid,
    )?;
    server_device.set_advertising_data(builder)?;
    server_device.start_advertising(true).await?;
    Ok((
        server_address,
        server_transport,
        server_device,
        read_handler,
        service_handle,
    ))
}

/// Connect to a GATT server and find the specified characteristic
///
/// Returns transport to keep it alive for the duration of the test
async fn connect_and_discover(
    transport_spec: String,
    service_uuid: Uuid128,
    characteristic_uuid: Uuid128,
    server_address: &Address,
) -> anyhow::Result<(Transport, CharacteristicProxy<Vec<u8>>)> {
    let client_transport = Transport::open(transport_spec).await?;
    let client_address =
        Address::from_be_hex("F0:F1:F2:F3:F4:F6", AddressType::RandomDeviceAddress)
            .map_err(|e| anyhow!(e))?;
    let client_device = Device::with_hci(
        "Bumble",
        client_address,
        client_transport.source()?,
        client_transport.sink()?,
    )
    .await?;
    client_device.power_on().await?;
    let conn = client_device.connect(server_address).await?;
    let mut peer = Peer::new(conn).await?;

    peer.discover_services().await?;
    peer.discover_characteristics().await?;

    let discovered_service = peer
        .services_by_uuid(service_uuid)?
        .into_iter()
        .next()
        .ok_or(anyhow!("Service not found"))?;

    let discovered_characteristic = discovered_service
        .characteristics_by_uuid(characteristic_uuid)?
        .into_iter()
        .next()
        .ok_or(anyhow!("Characteristic not found"))?;
    Ok((client_transport, discovered_characteristic))
}
