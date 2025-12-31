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
"""
Classes representing "Data Types" defined in
"Supplement to the Bluetooth Core Specification", Part A and
"Assigned Numbers", 2.3 Common Data Types.
"""

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from __future__ import annotations

import dataclasses
import math
import struct
from collections.abc import Sequence
from typing import Any, ClassVar

from typing_extensions import Self

from bumble import company_ids, core, hci


# -----------------------------------------------------------------------------
class GenericAdvertisingData(core.DataType):
    """Data Type for which there is no specific subclass"""

    label = "Generic Advertising Data"
    ad_data: bytes

    def __init__(self, ad_data: bytes, ad_type: core.AdvertisingData.Type) -> None:
        self.ad_data = ad_data
        self.ad_type = ad_type

    def value_string(self) -> str:
        return f"type={self.ad_type.name}, data={self.ad_data.hex().upper()}"

    @classmethod
    def from_bytes(
        cls,
        ad_data: bytes,
        ad_type: core.AdvertisingData.Type = core.AdvertisingData.Type(0),
    ) -> GenericAdvertisingData:
        return cls(ad_data, ad_type)

    def __bytes__(self) -> bytes:
        return self.ad_data

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, GenericAdvertisingData)
            and self.ad_type == other.ad_type
            and self.ad_data == other.ad_data
        )


@dataclasses.dataclass
class ListOfServiceUUIDs(core.DataType):
    """Base class for complete or incomplete lists of UUIDs."""

    _uuid_size: ClassVar[int] = 0
    uuids: Sequence[core.UUID]

    @classmethod
    def from_bytes(cls, data: bytes) -> ListOfServiceUUIDs:
        return cls(
            [
                core.UUID.from_bytes(data[x : x + cls._uuid_size])
                for x in range(0, len(data), cls._uuid_size)
            ]
        )

    def __post_init__(self) -> None:
        for uuid in self.uuids:
            if len(uuid.uuid_bytes) != self._uuid_size:
                raise TypeError("incompatible UUID type")

    def __bytes__(self) -> bytes:
        return b"".join(bytes(uuid) for uuid in self.uuids)

    def value_string(self) -> str:
        return ", ".join(list(map(str, self.uuids)))


class IncompleteListOf16BitServiceUUIDs(ListOfServiceUUIDs):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.1 SERVICE OR SERVICE CLASS UUID
    """

    _uuid_size = 2
    label = "Incomplete List Of 16-bit Service or Service Class UUIDs"
    ad_type = core.AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS


class CompleteListOf16BitServiceUUIDs(ListOfServiceUUIDs):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.1 SERVICE OR SERVICE CLASS UUID
    """

    _uuid_size = 2
    label = "Complete List Of 16-bit Service or Service Class UUIDs"
    ad_type = core.AdvertisingData.COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS


class IncompleteListOf32BitServiceUUIDs(ListOfServiceUUIDs):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.1 SERVICE OR SERVICE CLASS UUID
    """

    _uuid_size = 4
    label = "Incomplete List Of 32-bit Service or Service Class UUIDs"
    ad_type = core.AdvertisingData.INCOMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS


class CompleteListOf32BitServiceUUIDs(ListOfServiceUUIDs):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.1 SERVICE OR SERVICE CLASS UUID
    """

    _uuid_size = 4
    label = "Complete List Of 32-bit Service or Service Class UUIDs"
    ad_type = core.AdvertisingData.COMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS


class IncompleteListOf128BitServiceUUIDs(ListOfServiceUUIDs):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.1 SERVICE OR SERVICE CLASS UUID
    """

    _uuid_size = 16
    label = "Incomplete List Of 128-bit Service or Service Class UUIDs"
    ad_type = core.AdvertisingData.INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS


class CompleteListOf128BitServiceUUIDs(ListOfServiceUUIDs):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.1 SERVICE OR SERVICE CLASS UUID
    """

    _uuid_size = 16
    label = "Complete List Of 128-bit Service or Service Class UUIDs"
    ad_type = core.AdvertisingData.COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS


class StringDataType(str, core.DataType):
    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        return cls(data.decode("utf-8"))

    def __bytes__(self) -> bytes:
        return self.encode("utf-8")

    def __str__(self) -> str:
        return core.DataType.__str__(self)

    def value_string(self) -> str:
        return repr(self)


class CompleteLocalName(StringDataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.2 LOCAL NAME
    """

    label = "Complete Local Name"
    ad_type = core.AdvertisingData.COMPLETE_LOCAL_NAME


class ShortenedLocalName(StringDataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.2 LOCAL NAME
    """

    label = "Shortened Local Name"
    ad_type = core.AdvertisingData.SHORTENED_LOCAL_NAME


class Flags(int, core.DataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.3 FLAGS
    """

    label = "Flags"
    ad_type = core.AdvertisingData.FLAGS

    def __init__(self, flags: core.AdvertisingData.Flags) -> None:
        pass

    @classmethod
    def from_bytes(cls, data: bytes) -> Flags:  # type: ignore[override]
        return cls(core.AdvertisingData.Flags(int.from_bytes(data, byteorder="little")))

    def __bytes__(self) -> bytes:
        bytes_length = 1 if self == 0 else math.ceil(self.bit_length() / 8)
        return self.to_bytes(length=bytes_length, byteorder="little")

    def value_string(self) -> str:
        return core.AdvertisingData.Flags(self).composite_name


@dataclasses.dataclass
class ManufacturerSpecificData(core.DataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.4 MANUFACTURER SPECIFIC DATA
    """

    label = "Manufacturer Specific Data"
    ad_type = core.AdvertisingData.Type.MANUFACTURER_SPECIFIC_DATA

    company_identifier: int
    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> ManufacturerSpecificData:
        company_identifier = int.from_bytes(data[:2], "little")
        return cls(company_identifier, data[2:])

    def __bytes__(self) -> bytes:
        return self.company_identifier.to_bytes(2, "little") + self.data

    def value_string(self) -> str:
        if company := company_ids.COMPANY_IDENTIFIERS.get(self.company_identifier):
            company_str = repr(company)
        else:
            company_str = f'0x{self.company_identifier:04X}'
        return f"company={company_str}, data={self.data.hex().upper()}"


class FixedSizeIntDataType(int, core.DataType):
    _fixed_size: int = 0
    _signed: bool = False

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:  # type: ignore[override]
        if len(data) != cls._fixed_size:
            raise ValueError(f"data must be {cls._fixed_size} byte")
        return cls(int.from_bytes(data, byteorder="little", signed=cls._signed))

    def __bytes__(self) -> bytes:
        return self.to_bytes(
            length=self._fixed_size, byteorder="little", signed=self._signed
        )

    def value_string(self) -> str:
        return str(int(self))


class TxPowerLevel(FixedSizeIntDataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.5 TX POWER LEVEL
    """

    _fixed_size = 1
    _signed = True
    label = "TX Power Level"
    ad_type = core.AdvertisingData.Type.TX_POWER_LEVEL


class FixedSizeBytesDataType(bytes, core.DataType):
    _fixed_size: int = 0

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        if len(data) != cls._fixed_size:
            raise ValueError(f"data must be {cls._fixed_size} bytes")
        return cls(data)

    def value_string(self) -> str:
        return self.hex().upper()

    def __str__(self) -> str:
        return core.DataType.__str__(self)

    def __bytes__(self) -> bytes:  # pylint: disable=E0308
        # Python < 3.11 compatibility (before 3.11, the byte class does not have
        # a __bytes__ method).
        # Concatenate with an empty string to perform a direct conversion without
        # calling bytes() explicity, which may cause an infinite recursion.
        return b"" + self


class ClassOfDevice(core.ClassOfDevice, core.DataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.6 SECURE SIMPLE PAIRING OUT OF BAND (OOB)
    """

    label = "Class of Device"
    ad_type = core.AdvertisingData.Type.CLASS_OF_DEVICE

    @classmethod
    def from_bytes(cls, data: bytes) -> ClassOfDevice:
        return cls.from_int(int.from_bytes(data, byteorder="little"))

    def __bytes__(self) -> bytes:
        return int(self).to_bytes(3, byteorder="little")

    def __eq__(self, value: Any) -> bool:
        return core.ClassOfDevice.__eq__(self, value)

    def value_string(self) -> str:
        return (
            f"{self.major_service_classes_labels()},"
            f"{self.major_device_class_label()}/"
            f"{self.minor_device_class_label()}"
        )

    def __str__(self) -> str:
        return core.DataType.__str__(self)


class SecureSimplePairingHashC192(FixedSizeBytesDataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.6 SECURE SIMPLE PAIRING OUT OF BAND (OOB)
    """

    _fixed_size = 16
    label = "Secure Simple Pairing Hash C-192"
    ad_type = core.AdvertisingData.Type.SIMPLE_PAIRING_HASH_C_192


class SecureSimplePairingRandomizerR192(FixedSizeBytesDataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.6 SECURE SIMPLE PAIRING OUT OF BAND (OOB)
    """

    _fixed_size = 16
    label = "Secure Simple Pairing Randomizer R-192"
    ad_type = core.AdvertisingData.Type.SIMPLE_PAIRING_RANDOMIZER_R_192


class SecureSimplePairingHashC256(FixedSizeBytesDataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.6 SECURE SIMPLE PAIRING OUT OF BAND (OOB)
    """

    _fixed_size = 16
    label = "Secure Simple Pairing Hash C-256"
    ad_type = core.AdvertisingData.Type.SIMPLE_PAIRING_HASH_C_256


class SecureSimplePairingRandomizerR256(FixedSizeBytesDataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.6 SECURE SIMPLE PAIRING OUT OF BAND (OOB)
    """

    _fixed_size = 16
    label = "Secure Simple Pairing Randomizer R-256"
    ad_type = core.AdvertisingData.Type.SIMPLE_PAIRING_RANDOMIZER_R_256


class LeSecureConnectionsConfirmationValue(FixedSizeBytesDataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.6 SECURE SIMPLE PAIRING OUT OF BAND (OOB)
    """

    _fixed_size = 16
    label = "LE Secure Connections Confirmation Value"
    ad_type = core.AdvertisingData.Type.LE_SECURE_CONNECTIONS_CONFIRMATION_VALUE


class LeSecureConnectionsRandomValue(FixedSizeBytesDataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.6 SECURE SIMPLE PAIRING OUT OF BAND (OOB)
    """

    _fixed_size = 16
    label = "LE Secure Connections Random Value"
    ad_type = core.AdvertisingData.Type.LE_SECURE_CONNECTIONS_RANDOM_VALUE


class SecurityManagerOutOfBandFlag(int, core.DataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.7 SECURITY MANAGER OUT OF BAND (OOB)
    """

    label = "Security Manager Out of Band Flag"
    ad_type = core.AdvertisingData.Type.SECURITY_MANAGER_OUT_OF_BAND_FLAGS

    def __init__(self, flag: core.SecurityManagerOutOfBandFlag) -> None:
        pass

    @classmethod
    # type: ignore[override]
    def from_bytes(cls, data: bytes) -> SecurityManagerOutOfBandFlag:
        if len(data) != 1:
            raise ValueError("data must be 1 byte")
        return SecurityManagerOutOfBandFlag(core.SecurityManagerOutOfBandFlag(data[0]))

    def __bytes__(self) -> bytes:
        return bytes([self])

    def __str__(self) -> str:
        return core.DataType.__str__(self)

    def value_string(self) -> str:
        return core.SecurityManagerOutOfBandFlag(self).composite_name


class SecurityManagerTKValue(FixedSizeBytesDataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.8 SECURITY MANAGER TK VALUE
    """

    _fixed_size = 16
    label = "Security Manager TK Value"
    ad_type = core.AdvertisingData.Type.SECURITY_MANAGER_TK_VALUE


@dataclasses.dataclass
class PeripheralConnectionIntervalRange(core.DataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.9 PERIPHERAL CONNECTION INTERVAL RANGE
    """

    label = "Peripheral Connection Interval Range"
    ad_type = core.AdvertisingData.Type.PERIPHERAL_CONNECTION_INTERVAL_RANGE

    connection_interval_min: int
    connection_interval_max: int

    @classmethod
    def from_bytes(cls, data: bytes) -> PeripheralConnectionIntervalRange:
        return cls(*struct.unpack("<HH", data))

    def __bytes__(self) -> bytes:
        return struct.pack(
            "<HH", self.connection_interval_min, self.connection_interval_max
        )

    def value_string(self) -> str:
        return (
            f"connection_interval_min={self.connection_interval_min}, "
            f"connection_interval_max={self.connection_interval_max}"
        )


class ListOf16BitServiceSolicitationUUIDs(ListOfServiceUUIDs):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.10 SERVICE SOLICITATION
    """

    _uuid_size = 2
    label = "List of 16 bit Service Solicitation UUIDs"
    ad_type = core.AdvertisingData.Type.LIST_OF_16_BIT_SERVICE_SOLICITATION_UUIDS


class ListOf32BitServiceSolicitationUUIDs(ListOfServiceUUIDs):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.10 SERVICE SOLICITATION
    """

    _uuid_size = 4
    label = "List of 32 bit Service Solicitation UUIDs"
    ad_type = core.AdvertisingData.Type.LIST_OF_32_BIT_SERVICE_SOLICITATION_UUIDS


class ListOf128BitServiceSolicitationUUIDs(ListOfServiceUUIDs):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.10 SERVICE SOLICITATION
    """

    _uuid_size = 16
    label = "List of 128 bit Service Solicitation UUIDs"
    ad_type = core.AdvertisingData.Type.LIST_OF_128_BIT_SERVICE_SOLICITATION_UUIDS


@dataclasses.dataclass
class ServiceData(core.DataType):
    """Base class for service data lists of UUIDs."""

    _uuid_size: ClassVar[int] = 0

    service_uuid: core.UUID
    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        service_uuid = core.UUID.from_bytes(data[: cls._uuid_size])
        return cls(service_uuid, data[cls._uuid_size :])

    def __bytes__(self) -> bytes:
        return self.service_uuid.to_bytes() + self.data

    def value_string(self) -> str:
        return f"service={self.service_uuid}, data={self.data.hex().upper()}"


class ServiceData16BitUUID(ServiceData):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.11 SERVICE DATA
    """

    _uuid_size = 2
    label = "Service Data - 16 bit UUID"
    ad_type = core.AdvertisingData.Type.SERVICE_DATA_16_BIT_UUID


class ServiceData32BitUUID(ServiceData):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.11 SERVICE DATA
    """

    _uuid_size = 4
    label = "Service Data - 32 bit UUID"
    ad_type = core.AdvertisingData.Type.SERVICE_DATA_32_BIT_UUID


class ServiceData128BitUUID(ServiceData):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.11 SERVICE DATA
    """

    _uuid_size = 16
    label = "Service Data - 128 bit UUID"
    ad_type = core.AdvertisingData.Type.SERVICE_DATA_128_BIT_UUID


class Appearance(core.Appearance, core.DataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.12 APPEARANCE
    """

    label = "Appearance"
    ad_type = core.AdvertisingData.Type.APPEARANCE

    @classmethod
    def from_bytes(cls, data: bytes):
        return cls.from_int(int.from_bytes(data, byteorder="little"))

    def __bytes__(self) -> bytes:
        return int(self).to_bytes(2, byteorder="little")

    def __str__(self) -> str:
        return core.DataType.__str__(self)

    def value_string(self) -> str:
        return core.Appearance.__str__(self)


class PublicTargetAddress(hci.Address, core.DataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.13 PUBLIC TARGET ADDRESS
    """

    label = "Public Target Address"
    ad_type = core.AdvertisingData.Type.PUBLIC_TARGET_ADDRESS

    def __init__(self, address: hci.Address) -> None:
        self.address_bytes = address.address_bytes
        self.address_type = hci.Address.PUBLIC_DEVICE_ADDRESS

    @classmethod
    def from_bytes(cls, data: bytes) -> PublicTargetAddress:
        return cls(hci.Address(data))

    def __str__(self) -> str:
        return core.DataType.__str__(self)

    def to_string(self, use_label: bool = False) -> str:
        return core.DataType.to_string(self, use_label)

    def value_string(self) -> str:
        return hci.Address.to_string(self, with_type_qualifier=False)


class RandomTargetAddress(hci.Address, core.DataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.14 RANDOM TARGET ADDRESS
    """

    label = "Random Target Address"
    ad_type = core.AdvertisingData.Type.RANDOM_TARGET_ADDRESS

    def __init__(self, address: hci.Address) -> None:
        self.address_bytes = address.address_bytes
        self.address_type = hci.Address.RANDOM_DEVICE_ADDRESS

    @classmethod
    def from_bytes(cls, data: bytes) -> RandomTargetAddress:
        return cls(hci.Address(data))

    def __str__(self) -> str:
        return core.DataType.__str__(self)

    def to_string(self, use_label: bool = False) -> str:
        return core.DataType.to_string(self, use_label)

    def value_string(self) -> str:
        return hci.Address.to_string(self, with_type_qualifier=False)


class AdvertisingInterval(FixedSizeIntDataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.15 ADVERTISING INTERVAL
    """

    _fixed_size = 2
    label = "Advertising Interval"
    ad_type = core.AdvertisingData.Type.ADVERTISING_INTERVAL


class AdvertisingIntervalLong(int, core.DataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.15 ADVERTISING INTERVAL
    """

    label = "Advertising Interval - long"
    ad_type = core.AdvertisingData.Type.ADVERTISING_INTERVAL_LONG

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:  # type: ignore[override]
        return cls(int.from_bytes(data, byteorder="little"))

    def __bytes__(self) -> bytes:
        return self.to_bytes(length=4 if self >= 0x1000000 else 3, byteorder="little")

    def value_string(self) -> str:
        return str(int(self))


class LeBluetoothDeviceAddress(hci.Address, core.DataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.16 LE BLUETOOTH DEVICE ADDRESS
    """

    label = "LE Bluetooth Device Address"
    ad_type = core.AdvertisingData.Type.LE_BLUETOOTH_DEVICE_ADDRESS

    def __init__(self, address: hci.Address) -> None:
        self.address_bytes = address.address_bytes
        self.address_type = address.address_type

    @classmethod
    def from_bytes(cls, data: bytes) -> LeBluetoothDeviceAddress:
        return cls(hci.Address(data[1:], hci.AddressType(data[0])))

    def __bytes__(self) -> bytes:
        return bytes([self.address_type]) + self.address_bytes

    def __str__(self) -> str:
        return core.DataType.__str__(self)

    def to_string(self, use_label: bool = False) -> str:
        return core.DataType.to_string(self, use_label)

    def value_string(self) -> str:
        return (
            f"{hci.Address.to_string(self, with_type_qualifier=False)}"
            f"/{'PUBLIC' if self.is_public else 'RANDOM'}"
        )


class LeRole(int, core.DataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.17 LE ROLE
    """

    label = "LE Role"
    ad_type = core.AdvertisingData.Type.LE_ROLE

    def __init__(self, role: core.LeRole) -> None:
        pass

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:  # type: ignore[override]
        return cls(core.LeRole(data[0]))

    def __bytes__(self) -> bytes:
        return bytes([self])

    def value_string(self) -> str:
        return core.LeRole(self).name


class Uri(str, core.DataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.18 UNIFORM RESOURCE IDENTIFIER (URI)
    """

    label = "URI"
    ad_type = core.AdvertisingData.Type.URI

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        return cls(data.decode("utf-8"))

    def __bytes__(self):
        return self.encode("utf-8")

    def __str__(self) -> str:
        return core.DataType.__str__(self)

    def value_string(self) -> str:
        return repr(self)


class LeSupportedFeatures(int, core.DataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.19 LE SUPPORTED FEATURES
    """

    label = "LE Supported Features"
    ad_type = core.AdvertisingData.Type.LE_SUPPORTED_FEATURES

    @classmethod
    def from_bytes(cls, data: bytes) -> LeSupportedFeatures:  # type: ignore[override]
        return cls(int.from_bytes(data, byteorder="little"))

    def __bytes__(self) -> bytes:
        bytes_length = 1 if self == 0 else math.ceil(self.bit_length() / 8)
        return self.to_bytes(length=bytes_length, byteorder="little")

    def value_string(self) -> str:
        return hci.LeFeatureMask(self).composite_name


@dataclasses.dataclass
class ChannelMapUpdateIndication(core.DataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.20 CHANNEL MAP UPDATE INDICATION
    """

    label = "Channel Map Update Indication"
    ad_type = core.AdvertisingData.Type.CHANNEL_MAP_UPDATE_INDICATION

    chm: int
    instant: int

    @classmethod
    def from_bytes(cls, data: bytes) -> ChannelMapUpdateIndication:
        return cls(
            int.from_bytes(data[:5], byteorder="little"),
            int.from_bytes(data[5:7], byteorder="little"),
        )

    def __bytes__(self) -> bytes:
        return self.chm.to_bytes(5, byteorder="little") + self.instant.to_bytes(
            2, byteorder="little"
        )

    def value_string(self) -> str:
        return f"chm={self.chm:010X}, instant={self.instant}"


class BigInfo(core.DataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.21 BIGINFO
    """

    # TODO


class BroadcastCode(str, core.DataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.22 BROADCAST_CODE
    """

    label = "Broadcast Code"
    ad_type = core.AdvertisingData.Type.BROADCAST_CODE

    def __init__(self, value: str) -> None:
        encoded = value.encode("utf-8")
        if len(encoded) > 16:
            raise ValueError("broadcast code must be <= 16 bytes in utf-8 encoding")

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        return cls(data.strip(bytes([0])).decode("utf-8"))

    def __bytes__(self) -> bytes:
        return self.encode("utf-8")

    def __str__(self) -> str:
        return core.DataType.__str__(self)

    def value_string(self) -> str:
        return repr(self)


@dataclasses.dataclass
class EncryptedData(core.DataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.23 ENCRYPTED DATA
    """

    label = "Encrypted Data"
    ad_type = core.AdvertisingData.Type.ENCRYPTED_ADVERTISING_DATA

    randomizer: int
    payload: bytes
    mic: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> EncryptedData:
        randomizer = int.from_bytes(data[:5], byteorder="little")
        payload = data[5 : len(data) - 4]
        mic = data[-4:]
        return cls(randomizer, payload, mic)

    def __bytes__(self) -> bytes:
        return self.randomizer.to_bytes(5, byteorder="little") + self.payload + self.mic

    def value_string(self) -> str:
        return (
            f"randomizer=0x{self.randomizer:010X}, "
            f"payload={self.payload.hex().upper()}, "
            f"mic={self.mic.hex().upper()}"
        )


@dataclasses.dataclass
class PeriodicAdvertisingResponseTimingInformation(core.DataType):
    """
    See Supplement to the Bluetooth Core Specification, Part A
    1.24 PERIODIC ADVERTISING RESPONSE TIMING INFORMATION
    """

    label = "Periodic Advertising Response Timing Information"
    ad_type = core.AdvertisingData.Type.PERIODIC_ADVERTISING_RESPONSE_TIMING_INFORMATION

    rspaa: int
    num_subevents: int
    subevent_interval: int
    response_slot_delay: int
    response_slot_spacing: int

    @classmethod
    def from_bytes(cls, data: bytes) -> PeriodicAdvertisingResponseTimingInformation:
        return cls(
            int.from_bytes(data[:4], byteorder="little"),
            data[4],
            data[5],
            data[6],
            data[7],
        )

    def __bytes__(self) -> bytes:
        return self.rspaa.to_bytes(4, byteorder="little") + bytes(
            [
                self.num_subevents,
                self.subevent_interval,
                self.response_slot_delay,
                self.response_slot_spacing,
            ]
        )

    def value_string(self) -> str:
        return (
            f"rspaa=0x{self.rspaa:08X}, "
            f"num_subevents={self.num_subevents}, "
            f"subevent_interval={self.subevent_interval}, "
            f"response_slot_delay={self.response_slot_delay}, "
            f"response_slot_spacing={self.response_slot_spacing}"
        )


class BroadcastName(StringDataType):
    """
    See Assigned Numbers, 6.12.6.13 Broadcast_Name
    """

    label = "Broadcast Name"
    ad_type = core.AdvertisingData.Type.BROADCAST_NAME


class ResolvableSetIdentifier(FixedSizeBytesDataType):
    """
    See Coordinated Set Identification Service, 3.1 RSI AD Type
    """

    label = "Resolvable Set Identifier"
    ad_type = core.AdvertisingData.Type.RESOLVABLE_SET_IDENTIFIER
    _fixed_size = 6


# -----------------------------------------------------------------------------
_AD_TO_DATA_TYPE_CLASS_MAP: dict[core.AdvertisingData.Type, type[core.DataType]] = {
    core.AdvertisingData.Type.FLAGS: Flags,
    core.AdvertisingData.Type.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS: IncompleteListOf16BitServiceUUIDs,
    core.AdvertisingData.Type.COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS: CompleteListOf16BitServiceUUIDs,
    core.AdvertisingData.Type.INCOMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS: IncompleteListOf32BitServiceUUIDs,
    core.AdvertisingData.Type.COMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS: CompleteListOf32BitServiceUUIDs,
    core.AdvertisingData.Type.INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS: IncompleteListOf128BitServiceUUIDs,
    core.AdvertisingData.Type.COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS: CompleteListOf128BitServiceUUIDs,
    core.AdvertisingData.Type.SHORTENED_LOCAL_NAME: ShortenedLocalName,
    core.AdvertisingData.Type.COMPLETE_LOCAL_NAME: CompleteLocalName,
    core.AdvertisingData.Type.TX_POWER_LEVEL: TxPowerLevel,
    core.AdvertisingData.Type.CLASS_OF_DEVICE: ClassOfDevice,
    core.AdvertisingData.Type.SIMPLE_PAIRING_HASH_C_192: SecureSimplePairingHashC192,
    core.AdvertisingData.Type.SIMPLE_PAIRING_RANDOMIZER_R_192: SecureSimplePairingRandomizerR192,
    # core.AdvertisingData.Type.DEVICE_ID: TBD,
    core.AdvertisingData.Type.SECURITY_MANAGER_TK_VALUE: SecurityManagerTKValue,
    core.AdvertisingData.Type.SECURITY_MANAGER_OUT_OF_BAND_FLAGS: SecurityManagerOutOfBandFlag,
    core.AdvertisingData.Type.PERIPHERAL_CONNECTION_INTERVAL_RANGE: PeripheralConnectionIntervalRange,
    core.AdvertisingData.Type.LIST_OF_16_BIT_SERVICE_SOLICITATION_UUIDS: ListOf16BitServiceSolicitationUUIDs,
    core.AdvertisingData.Type.LIST_OF_128_BIT_SERVICE_SOLICITATION_UUIDS: ListOf128BitServiceSolicitationUUIDs,
    core.AdvertisingData.Type.SERVICE_DATA_16_BIT_UUID: ServiceData16BitUUID,
    core.AdvertisingData.Type.PUBLIC_TARGET_ADDRESS: PublicTargetAddress,
    core.AdvertisingData.Type.RANDOM_TARGET_ADDRESS: RandomTargetAddress,
    core.AdvertisingData.Type.APPEARANCE: Appearance,
    core.AdvertisingData.Type.ADVERTISING_INTERVAL: AdvertisingInterval,
    core.AdvertisingData.Type.LE_BLUETOOTH_DEVICE_ADDRESS: LeBluetoothDeviceAddress,
    core.AdvertisingData.Type.LE_ROLE: LeRole,
    core.AdvertisingData.Type.SIMPLE_PAIRING_HASH_C_256: SecureSimplePairingHashC256,
    core.AdvertisingData.Type.SIMPLE_PAIRING_RANDOMIZER_R_256: SecureSimplePairingRandomizerR256,
    core.AdvertisingData.Type.LIST_OF_32_BIT_SERVICE_SOLICITATION_UUIDS: ListOf32BitServiceSolicitationUUIDs,
    core.AdvertisingData.Type.SERVICE_DATA_32_BIT_UUID: ServiceData32BitUUID,
    core.AdvertisingData.Type.SERVICE_DATA_128_BIT_UUID: ServiceData128BitUUID,
    core.AdvertisingData.Type.LE_SECURE_CONNECTIONS_CONFIRMATION_VALUE: LeSecureConnectionsConfirmationValue,
    core.AdvertisingData.Type.LE_SECURE_CONNECTIONS_RANDOM_VALUE: LeSecureConnectionsRandomValue,
    core.AdvertisingData.Type.URI: Uri,
    # core.AdvertisingData.Type.INDOOR_POSITIONING: TBD,
    # core.AdvertisingData.Type.TRANSPORT_DISCOVERY_DATA: TBD,
    core.AdvertisingData.Type.LE_SUPPORTED_FEATURES: LeSupportedFeatures,
    core.AdvertisingData.Type.CHANNEL_MAP_UPDATE_INDICATION: ChannelMapUpdateIndication,
    # core.AdvertisingData.Type.PB_ADV: TBD,
    # core.AdvertisingData.Type.MESH_MESSAGE: TBD,
    # core.AdvertisingData.Type.MESH_BEACON: TBD,
    # core.AdvertisingData.Type.BIGINFO: BigInfo,
    core.AdvertisingData.Type.BROADCAST_CODE: BroadcastCode,
    core.AdvertisingData.Type.RESOLVABLE_SET_IDENTIFIER: ResolvableSetIdentifier,
    core.AdvertisingData.Type.ADVERTISING_INTERVAL_LONG: AdvertisingIntervalLong,
    core.AdvertisingData.Type.BROADCAST_NAME: BroadcastName,
    core.AdvertisingData.Type.ENCRYPTED_ADVERTISING_DATA: EncryptedData,
    core.AdvertisingData.Type.PERIODIC_ADVERTISING_RESPONSE_TIMING_INFORMATION: PeriodicAdvertisingResponseTimingInformation,
    # core.AdvertisingData.Type.ELECTRONIC_SHELF_LABEL: TBD,
    # core.AdvertisingData.Type.THREE_D_INFORMATION_DATA: TBD,
    core.AdvertisingData.Type.MANUFACTURER_SPECIFIC_DATA: ManufacturerSpecificData,
}


def data_type_from_advertising_data(
    advertising_data_type: core.AdvertisingData.Type,
    advertising_data: bytes,
) -> core.DataType:
    """
    Creates a DataType object given a type ID and serialized data.

    NOTE: in general, if you know the type ID, it is preferrable to simply call the
    `from_bytes` factory class method of the associated DataType class directly.
    For example, use BroadcastName.from_bytes(bn_data) rather than
    data_type_from_advertising_data(AdvertisingData.Type.BROADCAST_NAME, bn_data)

    Args:
      advertising_data_type: type ID of the data.
      advertising_data: serialized data.

    Returns:
      a DataType subclass instance.

    """
    if data_type_class := _AD_TO_DATA_TYPE_CLASS_MAP.get(advertising_data_type):
        return data_type_class.from_bytes(advertising_data)

    return GenericAdvertisingData(advertising_data, advertising_data_type)


def data_types_from_advertising_data(
    advertising_data: core.AdvertisingData,
) -> list[core.DataType]:
    """
    Create DataType objects representing all the advertising data structs contained
    in an AdvertisingData object.

    Args:
      advertising_data: the AdvertisingData in which to look for the data type.

    Returns:
      a list of DataType subclass instances.
    """
    return [
        data_type_from_advertising_data(ad_type, ad_data)
        for (ad_type, ad_data) in advertising_data.ad_structures
    ]
