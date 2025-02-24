# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from __future__ import annotations
import asyncio
import dataclasses
import functools
import enum
import logging
import os
import random
import struct
import sys
from typing import Any, List, Union

from bumble.device import Device, Peer
from bumble import transport
from bumble import gatt
from bumble import gatt_adapters
from bumble import gatt_client
from bumble import hci
from bumble import core


# -----------------------------------------------------------------------------
SERVICE_UUID = core.UUID("50DB505C-8AC4-4738-8448-3B1D9CC09CC5")
CHARACTERISTIC_UUID_BASE = "D901B45B-4916-412E-ACCA-0000000000"

DEFAULT_CLIENT_ADDRESS = "F0:F1:F2:F3:F4:F5"
DEFAULT_SERVER_ADDRESS = "F1:F2:F3:F4:F5:F6"


# -----------------------------------------------------------------------------
@dataclasses.dataclass
class CustomSerializableClass:
    x: int
    y: int

    @classmethod
    def from_bytes(cls, data: bytes) -> CustomSerializableClass:
        return cls(*struct.unpack(">II", data))

    def __bytes__(self) -> bytes:
        return struct.pack(">II", self.x, self.y)


# -----------------------------------------------------------------------------
@dataclasses.dataclass
class CustomClass:
    a: int
    b: int

    @classmethod
    def decode(cls, data: bytes) -> CustomClass:
        return cls(*struct.unpack(">II", data))

    def encode(self) -> bytes:
        return struct.pack(">II", self.a, self.b)


# -----------------------------------------------------------------------------
class CustomEnum(enum.IntEnum):
    FOO = 1234
    BAR = 5678


# -----------------------------------------------------------------------------
async def client(device: Device, address: hci.Address) -> None:
    print(f'=== Connecting to {address}...')
    connection = await device.connect(address)
    print('=== Connected')

    # Discover all characteristics.
    peer = Peer(connection)
    print("*** Discovering services and characteristics...")
    await peer.discover_all()
    print("*** Discovery complete")

    service = peer.get_services_by_uuid(SERVICE_UUID)[0]
    characteristics: list[gatt_client.CharacteristicProxy] = []
    for index in range(1, 10):
        characteristics.append(
            service.get_characteristics_by_uuid(
                core.UUID(CHARACTERISTIC_UUID_BASE + f"{index:02X}")
            )[0]
        )

    # Read all characteristics as raw bytes.
    for characteristic in characteristics:
        value = await characteristic.read_value()
        print(f"### {characteristic} = {value!r} ({value.hex()})")

    # Subscribe to all characteristics as a raw bytes listener.
    def on_raw_characteristic_update(characteristic, value):
        print(f"^^^ Update[RAW] {characteristic.uuid} value = {value.hex()}")

    for characteristic in characteristics:
        await characteristic.subscribe(
            functools.partial(on_raw_characteristic_update, characteristic)
        )

    # Function to subscribe to adapted characteristics
    def on_adapted_characteristic_update(characteristic, value):
        print(
            f"^^^ Update[ADAPTED] {characteristic.uuid} value = {value!r}, "
            f"type={type(value)}"
        )

    # Static characteristic with a bytes value.
    c1 = characteristics[0]
    c1_value = await c1.read_value()
    print(f"@@@ C1 {c1} value = {c1_value!r} (type={type(c1_value)})")
    await c1.write_value("happy π day".encode("utf-8"))
    await c1.subscribe(functools.partial(on_adapted_characteristic_update, c1))

    # Static characteristic with a string value.
    c2 = gatt_adapters.UTF8CharacteristicProxyAdapter(characteristics[1])
    c2_value = await c2.read_value()
    print(f"@@@ C2 {c2} value = {c2_value} (type={type(c2_value)})")
    await c2.write_value("happy π day")
    await c2.subscribe(functools.partial(on_adapted_characteristic_update, c2))

    # Static characteristic with a tuple value.
    c3 = gatt_adapters.PackedCharacteristicProxyAdapter(characteristics[2], ">III")
    c3_value = await c3.read_value()
    print(f"@@@ C3 {c3} value = {c3_value} (type={type(c3_value)})")
    await c3.write_value((2001, 2002, 2003))
    await c3.subscribe(functools.partial(on_adapted_characteristic_update, c3))

    # Static characteristic with a named tuple value.
    c4 = gatt_adapters.MappedCharacteristicProxyAdapter(
        characteristics[3], ">III", ["f1", "f2", "f3"]
    )
    c4_value = await c4.read_value()
    print(f"@@@ C4 {c4} value = {c4_value} (type={type(c4_value)})")
    await c4.write_value({"f1": 4001, "f2": 4002, "f3": 4003})
    await c4.subscribe(functools.partial(on_adapted_characteristic_update, c4))

    # Static characteristic with a serializable value.
    c5 = gatt_adapters.SerializableCharacteristicProxyAdapter(
        characteristics[4], CustomSerializableClass
    )
    c5_value = await c5.read_value()
    print(f"@@@ C5 {c5} value = {c5_value} (type={type(c5_value)})")
    await c5.write_value(CustomSerializableClass(56, 57))
    await c5.subscribe(functools.partial(on_adapted_characteristic_update, c5))

    # Static characteristic with a delegated value.
    c6 = gatt_adapters.DelegatedCharacteristicProxyAdapter(
        characteristics[5], encode=CustomClass.encode, decode=CustomClass.decode
    )
    c6_value = await c6.read_value()
    print(f"@@@ C6 {c6} value = {c6_value} (type={type(c6_value)})")
    await c6.write_value(CustomClass(6, 7))
    await c6.subscribe(functools.partial(on_adapted_characteristic_update, c6))

    # Dynamic characteristic with a bytes value.
    c7 = characteristics[6]
    c7_value = await c7.read_value()
    print(f"@@@ C7 {c7} value = {c7_value!r} (type={type(c7_value)})")
    await c7.write_value(bytes.fromhex("01020304"))
    await c7.subscribe(functools.partial(on_adapted_characteristic_update, c7))

    # Dynamic characteristic with a string value.
    c8 = gatt_adapters.UTF8CharacteristicProxyAdapter(characteristics[7])
    c8_value = await c8.read_value()
    print(f"@@@ C8 {c8} value = {c8_value} (type={type(c8_value)})")
    await c8.write_value("howdy")
    await c8.subscribe(functools.partial(on_adapted_characteristic_update, c8))

    # Static characteristic with an enum value
    c9 = gatt_adapters.EnumCharacteristicProxyAdapter(
        characteristics[8], CustomEnum, 3, 'big'
    )
    c9_value = await c9.read_value()
    print(f"@@@ C9 {c9} value = {c9_value.name} (type={type(c9_value)})")
    await c9.write_value(CustomEnum.BAR)
    await c9.subscribe(functools.partial(on_adapted_characteristic_update, c9))


# -----------------------------------------------------------------------------
def dynamic_read(selector: str) -> Union[bytes, str]:
    if selector == "bytes":
        print("$$$ Returning random bytes")
        return random.randbytes(7)
    elif selector == "string":
        print("$$$ Returning random string")
        return random.randbytes(7).hex()

    raise ValueError("invalid selector")


# -----------------------------------------------------------------------------
def dynamic_write(selector: str, value: Any) -> None:
    print(f"$$$ Received[{selector}]: {value} (type={type(value)})")


# -----------------------------------------------------------------------------
def on_characteristic_read(characteristic: gatt.Characteristic, value: Any) -> None:
    """Event listener invoked when a characteristic is read."""
    print(f"<<< READ: {characteristic} -> {value} ({type(value)})")


# -----------------------------------------------------------------------------
def on_characteristic_write(characteristic: gatt.Characteristic, value: Any) -> None:
    """Event listener invoked when a characteristic is written."""
    print(f"<<< WRITE: {characteristic} <- {value}  ({type(value)})")


# -----------------------------------------------------------------------------
async def server(device: Device) -> None:
    # Static characteristic with a bytes value.
    c1 = gatt.Characteristic(
        CHARACTERISTIC_UUID_BASE + "01",
        gatt.Characteristic.Properties.READ
        | gatt.Characteristic.Properties.WRITE
        | gatt.Characteristic.Properties.NOTIFY,
        gatt.Characteristic.READABLE | gatt.Characteristic.WRITEABLE,
        b'hello',
    )

    # Static characteristic with a string value.
    c2 = gatt_adapters.UTF8CharacteristicAdapter(
        gatt.Characteristic(
            CHARACTERISTIC_UUID_BASE + "02",
            gatt.Characteristic.Properties.READ
            | gatt.Characteristic.Properties.WRITE
            | gatt.Characteristic.Properties.NOTIFY,
            gatt.Characteristic.READABLE | gatt.Characteristic.WRITEABLE,
            'hello',
        )
    )

    # Static characteristic with a tuple value.
    c3 = gatt_adapters.PackedCharacteristicAdapter(
        gatt.Characteristic(
            CHARACTERISTIC_UUID_BASE + "03",
            gatt.Characteristic.Properties.READ
            | gatt.Characteristic.Properties.WRITE
            | gatt.Characteristic.Properties.NOTIFY,
            gatt.Characteristic.READABLE | gatt.Characteristic.WRITEABLE,
            (1007, 1008, 1009),
        ),
        ">III",
    )

    # Static characteristic with a named tuple value.
    c4 = gatt_adapters.MappedCharacteristicAdapter(
        gatt.Characteristic(
            CHARACTERISTIC_UUID_BASE + "04",
            gatt.Characteristic.Properties.READ
            | gatt.Characteristic.Properties.WRITE
            | gatt.Characteristic.Properties.NOTIFY,
            gatt.Characteristic.READABLE | gatt.Characteristic.WRITEABLE,
            {"f1": 3007, "f2": 3008, "f3": 3009},
        ),
        ">III",
        ["f1", "f2", "f3"],
    )

    # Static characteristic with a serializable value.
    c5 = gatt_adapters.SerializableCharacteristicAdapter(
        gatt.Characteristic(
            CHARACTERISTIC_UUID_BASE + "05",
            gatt.Characteristic.Properties.READ
            | gatt.Characteristic.Properties.WRITE
            | gatt.Characteristic.Properties.NOTIFY,
            gatt.Characteristic.READABLE | gatt.Characteristic.WRITEABLE,
            CustomSerializableClass(11, 12),
        ),
        CustomSerializableClass,
    )

    # Static characteristic with a delegated value.
    c6 = gatt_adapters.DelegatedCharacteristicAdapter(
        gatt.Characteristic(
            CHARACTERISTIC_UUID_BASE + "06",
            gatt.Characteristic.Properties.READ
            | gatt.Characteristic.Properties.WRITE
            | gatt.Characteristic.Properties.NOTIFY,
            gatt.Characteristic.READABLE | gatt.Characteristic.WRITEABLE,
            CustomClass(1, 2),
        ),
        encode=CustomClass.encode,
        decode=CustomClass.decode,
    )

    # Dynamic characteristic with a bytes value.
    c7 = gatt.Characteristic(
        CHARACTERISTIC_UUID_BASE + "07",
        gatt.Characteristic.Properties.READ
        | gatt.Characteristic.Properties.WRITE
        | gatt.Characteristic.Properties.NOTIFY,
        gatt.Characteristic.READABLE | gatt.Characteristic.WRITEABLE,
        gatt.CharacteristicValue(
            read=lambda connection: dynamic_read("bytes"),
            write=lambda connection, value: dynamic_write("bytes", value),
        ),
    )

    # Dynamic characteristic with a string value.
    c8 = gatt_adapters.UTF8CharacteristicAdapter(
        gatt.Characteristic(
            CHARACTERISTIC_UUID_BASE + "08",
            gatt.Characteristic.Properties.READ
            | gatt.Characteristic.Properties.WRITE
            | gatt.Characteristic.Properties.NOTIFY,
            gatt.Characteristic.READABLE | gatt.Characteristic.WRITEABLE,
            gatt.CharacteristicValue(
                read=lambda connection: dynamic_read("string"),
                write=lambda connection, value: dynamic_write("string", value),
            ),
        )
    )

    # Static characteristic with an enum value
    c9 = gatt_adapters.EnumCharacteristicAdapter(
        gatt.Characteristic(
            CHARACTERISTIC_UUID_BASE + "09",
            gatt.Characteristic.Properties.READ
            | gatt.Characteristic.Properties.WRITE
            | gatt.Characteristic.Properties.NOTIFY,
            gatt.Characteristic.READABLE | gatt.Characteristic.WRITEABLE,
            CustomEnum.FOO,
        ),
        cls=CustomEnum,
        length=3,
        byteorder='big',
    )

    characteristics: List[gatt.Characteristic] = [
        c1,
        c2,
        c3,
        c4,
        c5,
        c6,
        c7,
        c8,
        c9,
    ]

    # Listen for read and write events.
    for characteristic in characteristics:
        characteristic.on(
            "read",
            lambda _, value, c=characteristic: on_characteristic_read(c, value),
        )
        characteristic.on(
            "write",
            lambda _, value, c=characteristic: on_characteristic_write(c, value),
        )

    device.add_service(gatt.Service(SERVICE_UUID, characteristics))

    # Notify every 3 seconds
    i = 0
    while True:
        await asyncio.sleep(3)

        # Notifying can be done with the characteristic's current value, or
        # by explicitly passing a value to notify with. Both variants are used
        # here: for c1..c4 we set the value and then notify, for c4..c9 we notify
        # with an explicit value.
        c1.value = f'hello c1 {i}'.encode()
        await device.notify_subscribers(c1)
        c2.value = f'hello c2 {i}'
        await device.notify_subscribers(c2)
        c3.value = (1000 + i, 2000 + i, 3000 + i)
        await device.notify_subscribers(c3)
        c4.value = {"f1": 4000 + i, "f2": 5000 + i, "f3": 6000 + i}
        await device.notify_subscribers(c4)
        await device.notify_subscribers(c5, CustomSerializableClass(1000 + i, 2000 + i))
        await device.notify_subscribers(c6, CustomClass(3000 + i, 4000 + i))
        await device.notify_subscribers(c7, bytes([1, 2, 3, i % 256]))
        await device.notify_subscribers(c8, f'hello c8 {i}')
        await device.notify_subscribers(
            c9, CustomEnum.FOO if i % 2 == 0 else CustomEnum.BAR
        )

        i += 1


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: run_gatt_with_adapters.py <transport-spec> client|server")
        print("example: run_gatt_with_adapters.py usb:0 F0:F1:F2:F3:F4:F5")
        return

    async with await transport.open_transport(sys.argv[1]) as hci_transport:
        is_client = sys.argv[2] == "client"

        # Create a device to manage the host
        device = Device.with_hci(
            "Bumble",
            hci.Address(
                DEFAULT_CLIENT_ADDRESS if is_client else DEFAULT_SERVER_ADDRESS
            ),
            hci_transport.source,
            hci_transport.sink,
        )

        # Get things going
        await device.power_on()

        if is_client:
            # Connect a client to a peer
            await client(device, hci.Address(DEFAULT_SERVER_ADDRESS))
        else:
            # Advertise so a peer can connect
            await device.start_advertising(auto_restart=True)

            # Setup a server
            await server(device)

        await hci_transport.source.wait_for_termination()


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
asyncio.run(main())
