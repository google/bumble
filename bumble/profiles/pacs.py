# Copyright 2024 Google LLC
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
# See the License for

"""LE Audio - Published Audio Capabilities Service"""

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from __future__ import annotations
import dataclasses
import logging
import struct
from typing import Optional, Sequence, Union

from bumble.profiles.bap import AudioLocation, CodecSpecificCapabilities, ContextType
from bumble.profiles import le_audio
from bumble import gatt
from bumble import gatt_adapters
from bumble import gatt_client
from bumble import hci


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
@dataclasses.dataclass
class PacRecord:
    '''Published Audio Capabilities Service, Table 3.2/3.4.'''

    coding_format: hci.CodingFormat
    codec_specific_capabilities: Union[CodecSpecificCapabilities, bytes]
    metadata: le_audio.Metadata = dataclasses.field(default_factory=le_audio.Metadata)

    @classmethod
    def from_bytes(cls, data: bytes) -> PacRecord:
        offset, coding_format = hci.CodingFormat.parse_from_bytes(data, 0)
        codec_specific_capabilities_size = data[offset]

        offset += 1
        codec_specific_capabilities_bytes = data[
            offset : offset + codec_specific_capabilities_size
        ]
        offset += codec_specific_capabilities_size
        metadata_size = data[offset]
        offset += 1
        metadata = le_audio.Metadata.from_bytes(data[offset : offset + metadata_size])

        codec_specific_capabilities: Union[CodecSpecificCapabilities, bytes]
        if coding_format.codec_id == hci.CodecID.VENDOR_SPECIFIC:
            codec_specific_capabilities = codec_specific_capabilities_bytes
        else:
            codec_specific_capabilities = CodecSpecificCapabilities.from_bytes(
                codec_specific_capabilities_bytes
            )

        return PacRecord(
            coding_format=coding_format,
            codec_specific_capabilities=codec_specific_capabilities,
            metadata=metadata,
        )

    @classmethod
    def list_from_bytes(cls, data: bytes) -> list[PacRecord]:
        """Parse a serialized list of records preceded by a one byte list length."""
        record_count = data[0]
        records = []
        offset = 1
        for _ in range(record_count):
            record = PacRecord.from_bytes(data[offset:])
            offset += len(bytes(record))
            records.append(record)

        return records

    def __bytes__(self) -> bytes:
        capabilities_bytes = bytes(self.codec_specific_capabilities)
        metadata_bytes = bytes(self.metadata)
        return (
            bytes(self.coding_format)
            + bytes([len(capabilities_bytes)])
            + capabilities_bytes
            + bytes([len(metadata_bytes)])
            + metadata_bytes
        )


# -----------------------------------------------------------------------------
# Server
# -----------------------------------------------------------------------------
class PublishedAudioCapabilitiesService(gatt.TemplateService):
    UUID = gatt.GATT_PUBLISHED_AUDIO_CAPABILITIES_SERVICE

    sink_pac: Optional[gatt.Characteristic[bytes]]
    sink_audio_locations: Optional[gatt.Characteristic[bytes]]
    source_pac: Optional[gatt.Characteristic[bytes]]
    source_audio_locations: Optional[gatt.Characteristic[bytes]]
    available_audio_contexts: gatt.Characteristic[bytes]
    supported_audio_contexts: gatt.Characteristic[bytes]

    def __init__(
        self,
        supported_source_context: ContextType,
        supported_sink_context: ContextType,
        available_source_context: ContextType,
        available_sink_context: ContextType,
        sink_pac: Sequence[PacRecord] = (),
        sink_audio_locations: Optional[AudioLocation] = None,
        source_pac: Sequence[PacRecord] = (),
        source_audio_locations: Optional[AudioLocation] = None,
    ) -> None:
        characteristics = []

        self.supported_audio_contexts = gatt.Characteristic(
            uuid=gatt.GATT_SUPPORTED_AUDIO_CONTEXTS_CHARACTERISTIC,
            properties=gatt.Characteristic.Properties.READ,
            permissions=gatt.Characteristic.Permissions.READABLE,
            value=struct.pack('<HH', supported_sink_context, supported_source_context),
        )
        characteristics.append(self.supported_audio_contexts)

        self.available_audio_contexts = gatt.Characteristic(
            uuid=gatt.GATT_AVAILABLE_AUDIO_CONTEXTS_CHARACTERISTIC,
            properties=gatt.Characteristic.Properties.READ
            | gatt.Characteristic.Properties.NOTIFY,
            permissions=gatt.Characteristic.Permissions.READABLE,
            value=struct.pack('<HH', available_sink_context, available_source_context),
        )
        characteristics.append(self.available_audio_contexts)

        if sink_pac:
            self.sink_pac = gatt.Characteristic(
                uuid=gatt.GATT_SINK_PAC_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.READ,
                permissions=gatt.Characteristic.Permissions.READABLE,
                value=bytes([len(sink_pac)]) + b''.join(map(bytes, sink_pac)),
            )
            characteristics.append(self.sink_pac)

        if sink_audio_locations is not None:
            self.sink_audio_locations = gatt.Characteristic(
                uuid=gatt.GATT_SINK_AUDIO_LOCATION_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.READ,
                permissions=gatt.Characteristic.Permissions.READABLE,
                value=struct.pack('<I', sink_audio_locations),
            )
            characteristics.append(self.sink_audio_locations)

        if source_pac:
            self.source_pac = gatt.Characteristic(
                uuid=gatt.GATT_SOURCE_PAC_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.READ,
                permissions=gatt.Characteristic.Permissions.READABLE,
                value=bytes([len(source_pac)]) + b''.join(map(bytes, source_pac)),
            )
            characteristics.append(self.source_pac)

        if source_audio_locations is not None:
            self.source_audio_locations = gatt.Characteristic(
                uuid=gatt.GATT_SOURCE_AUDIO_LOCATION_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.READ,
                permissions=gatt.Characteristic.Permissions.READABLE,
                value=struct.pack('<I', source_audio_locations),
            )
            characteristics.append(self.source_audio_locations)

        super().__init__(characteristics)


# -----------------------------------------------------------------------------
# Client
# -----------------------------------------------------------------------------
class PublishedAudioCapabilitiesServiceProxy(gatt_client.ProfileServiceProxy):
    SERVICE_CLASS = PublishedAudioCapabilitiesService

    sink_pac: Optional[gatt_client.CharacteristicProxy[list[PacRecord]]] = None
    sink_audio_locations: Optional[gatt_client.CharacteristicProxy[AudioLocation]] = (
        None
    )
    source_pac: Optional[gatt_client.CharacteristicProxy[list[PacRecord]]] = None
    source_audio_locations: Optional[gatt_client.CharacteristicProxy[AudioLocation]] = (
        None
    )
    available_audio_contexts: gatt_client.CharacteristicProxy[tuple[ContextType, ...]]
    supported_audio_contexts: gatt_client.CharacteristicProxy[tuple[ContextType, ...]]

    def __init__(self, service_proxy: gatt_client.ServiceProxy):
        self.service_proxy = service_proxy

        self.available_audio_contexts = (
            gatt_adapters.DelegatedCharacteristicProxyAdapter(
                service_proxy.get_required_characteristic_by_uuid(
                    gatt.GATT_AVAILABLE_AUDIO_CONTEXTS_CHARACTERISTIC
                ),
                decode=lambda x: tuple(map(ContextType, struct.unpack('<HH', x))),
            )
        )

        self.supported_audio_contexts = (
            gatt_adapters.DelegatedCharacteristicProxyAdapter(
                service_proxy.get_required_characteristic_by_uuid(
                    gatt.GATT_SUPPORTED_AUDIO_CONTEXTS_CHARACTERISTIC
                ),
                decode=lambda x: tuple(map(ContextType, struct.unpack('<HH', x))),
            )
        )

        if characteristics := service_proxy.get_characteristics_by_uuid(
            gatt.GATT_SINK_PAC_CHARACTERISTIC
        ):
            self.sink_pac = gatt_adapters.DelegatedCharacteristicProxyAdapter(
                characteristics[0],
                decode=PacRecord.list_from_bytes,
            )

        if characteristics := service_proxy.get_characteristics_by_uuid(
            gatt.GATT_SOURCE_PAC_CHARACTERISTIC
        ):
            self.source_pac = gatt_adapters.DelegatedCharacteristicProxyAdapter(
                characteristics[0],
                decode=PacRecord.list_from_bytes,
            )

        if characteristics := service_proxy.get_characteristics_by_uuid(
            gatt.GATT_SINK_AUDIO_LOCATION_CHARACTERISTIC
        ):
            self.sink_audio_locations = (
                gatt_adapters.DelegatedCharacteristicProxyAdapter(
                    characteristics[0],
                    decode=lambda x: AudioLocation(struct.unpack('<I', x)[0]),
                )
            )

        if characteristics := service_proxy.get_characteristics_by_uuid(
            gatt.GATT_SOURCE_AUDIO_LOCATION_CHARACTERISTIC
        ):
            self.source_audio_locations = (
                gatt_adapters.DelegatedCharacteristicProxyAdapter(
                    characteristics[0],
                    decode=lambda x: AudioLocation(struct.unpack('<I', x)[0]),
                )
            )
