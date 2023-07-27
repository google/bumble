# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Generic & dependency free Bumble (reference) device."""

from bumble import transport
from bumble.core import (
    BT_GENERIC_AUDIO_SERVICE,
    BT_HANDSFREE_SERVICE,
    BT_L2CAP_PROTOCOL_ID,
    BT_RFCOMM_PROTOCOL_ID,
)
from bumble.device import Device, DeviceConfiguration
from bumble.hci import HCI_Reset_Command
from bumble.host import Host
from bumble.sdp import (
    SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
    SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
    DataElement,
    ServiceAttribute,
)
from typing import Any, Dict, List, Optional


class PandoraDevice:
    """
    Small wrapper around a Bumble device and it's HCI transport.
    Notes:
      - The Bumble device is idle by default.
      - Repetitive calls to `open`/`close` will result on new Bumble device instances.
    """

    # Bumble device instance & configuration.
    device: Device
    config: Dict[str, Any]

    # HCI transport name & instance.
    _hci_name: str
    _hci: Optional[transport.Transport]  # type: ignore[name-defined]

    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        self.device = _make_device(config)
        self._hci_name = config.get('transport', '')
        self._hci = None

    @property
    def idle(self) -> bool:
        return self.device._host is None  # type: ignore

    async def open(self) -> None:
        if self._hci is not None:
            return

        # open HCI transport
        self._hci = await transport.open_transport(self._hci_name)

    async def start(self) -> None:
        if not self.idle:
            return

        # open HCI transport
        await self.open()
        assert self._hci is not None

        # set device host.
        self.device.host = Host(controller_source=self._hci.source, controller_sink=self._hci.sink)  # type: ignore[no-untyped-call]

        # power-on.
        await self.device.power_on()

    async def stop(self) -> None:
        if self.idle:
            return

        # reset, flush & re-initialize device.
        await self.device.host.send_command(HCI_Reset_Command())  # type: ignore
        await self.device.host.flush()
        self.device.host = None  # type: ignore[assignment]
        self.device = _make_device(self.config)

    async def reset(self) -> None:
        await self.stop()
        await self.start()

    async def close(self) -> None:
        if self._hci is None:
            return

        await self._hci.close()  # type: ignore
        self._hci = None

    def info(self) -> Optional[Dict[str, str]]:
        return {
            'public_bd_address': str(self.device.public_address),
            'random_address': str(self.device.random_address),
        }


def _make_device(config: Dict[str, Any]) -> Device:
    """Initialize an idle Bumble device instance."""

    # initialize bumble device.
    device_config = DeviceConfiguration()
    device_config.load_from_dict(config)
    device = Device(config=device_config, host=None)

    # Add fake a2dp service to avoid Android disconnect
    device.sdp_service_records = _make_sdp_records(1)

    return device


# TODO(b/267540823): remove when Pandora A2dp is supported
def _make_sdp_records(rfcomm_channel: int) -> Dict[int, List[ServiceAttribute]]:
    return {
        0x00010001: [
            ServiceAttribute(
                SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
                DataElement.unsigned_integer_32(0x00010001),
            ),
            ServiceAttribute(
                SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
                DataElement.sequence(
                    [
                        DataElement.uuid(BT_HANDSFREE_SERVICE),
                        DataElement.uuid(BT_GENERIC_AUDIO_SERVICE),
                    ]
                ),
            ),
            ServiceAttribute(
                SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                DataElement.sequence(
                    [
                        DataElement.sequence([DataElement.uuid(BT_L2CAP_PROTOCOL_ID)]),
                        DataElement.sequence(
                            [
                                DataElement.uuid(BT_RFCOMM_PROTOCOL_ID),
                                DataElement.unsigned_integer_8(rfcomm_channel),
                            ]
                        ),
                    ]
                ),
            ),
            ServiceAttribute(
                SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                DataElement.sequence(
                    [
                        DataElement.sequence(
                            [
                                DataElement.uuid(BT_HANDSFREE_SERVICE),
                                DataElement.unsigned_integer_16(0x0105),
                            ]
                        )
                    ]
                ),
            ),
        ]
    }
