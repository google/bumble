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
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Support for Intel USB controllers.
Loosely based on the Fuchsia OS implementation.
"""

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from __future__ import annotations
import asyncio
import collections
import dataclasses
import logging
import os
import pathlib
import platform
import struct
from typing import Any, Deque, Optional, TYPE_CHECKING

from bumble import core
from bumble.drivers import common
from bumble import hci
from bumble import utils

if TYPE_CHECKING:
    from bumble.host import Host


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Constant
# -----------------------------------------------------------------------------

INTEL_USB_PRODUCTS = {
    (0x8087, 0x0032),  # AX210
    (0x8087, 0x0036),  # BE200
}

INTEL_FW_IMAGE_NAMES = [
    "ibt-0040-0041",
    "ibt-0040-1020",
    "ibt-0040-1050",
    "ibt-0040-2120",
    "ibt-0040-4150",
    "ibt-0041-0041",
    "ibt-0180-0041",
    "ibt-0180-1050",
    "ibt-0180-4150",
    "ibt-0291-0291",
    "ibt-1040-0041",
    "ibt-1040-1020",
    "ibt-1040-1050",
    "ibt-1040-2120",
    "ibt-1040-4150",
]

INTEL_FIRMWARE_DIR_ENV = "BUMBLE_INTEL_FIRMWARE_DIR"
INTEL_LINUX_FIRMWARE_DIR = "/lib/firmware/intel"

_MAX_FRAGMENT_SIZE = 252
_POST_RESET_DELAY = 0.2

# -----------------------------------------------------------------------------
# HCI Commands
# -----------------------------------------------------------------------------
HCI_INTEL_WRITE_DEVICE_CONFIG_COMMAND = hci.hci_vendor_command_op_code(0x008B)
HCI_INTEL_READ_VERSION_COMMAND = hci.hci_vendor_command_op_code(0x0005)
HCI_INTEL_RESET_COMMAND = hci.hci_vendor_command_op_code(0x0001)
HCI_INTEL_SECURE_SEND_COMMAND = hci.hci_vendor_command_op_code(0x0009)
HCI_INTEL_WRITE_BOOT_PARAMS_COMMAND = hci.hci_vendor_command_op_code(0x000E)

hci.HCI_Command.register_commands(globals())


@hci.HCI_Command.command(
    fields=[
        ("param0", 1),
    ],
    return_parameters_fields=[
        ("status", hci.STATUS_SPEC),
        ("tlv", "*"),
    ],
)
class HCI_Intel_Read_Version_Command(hci.HCI_Command):
    pass


@hci.HCI_Command.command(
    fields=[("data_type", 1), ("data", "*")],
    return_parameters_fields=[
        ("status", 1),
    ],
)
class Hci_Intel_Secure_Send_Command(hci.HCI_Command):
    pass


@hci.HCI_Command.command(
    fields=[
        ("reset_type", 1),
        ("patch_enable", 1),
        ("ddc_reload", 1),
        ("boot_option", 1),
        ("boot_address", 4),
    ],
    return_parameters_fields=[
        ("data", "*"),
    ],
)
class HCI_Intel_Reset_Command(hci.HCI_Command):
    pass


@hci.HCI_Command.command(
    fields=[("data", "*")],
    return_parameters_fields=[
        ("status", hci.STATUS_SPEC),
        ("params", "*"),
    ],
)
class Hci_Intel_Write_Device_Config_Command(hci.HCI_Command):
    pass


# -----------------------------------------------------------------------------
# Functions
# -----------------------------------------------------------------------------
def intel_firmware_dir() -> pathlib.Path:
    """
    Returns:
        A path to a subdir of the project data dir for Intel firmware.
         The directory is created if it doesn't exist.
    """
    from bumble.drivers import project_data_dir

    p = project_data_dir() / "firmware" / "intel"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _find_binary_path(file_name: str) -> pathlib.Path | None:
    # First check if an environment variable is set
    if INTEL_FIRMWARE_DIR_ENV in os.environ:
        if (
            path := pathlib.Path(os.environ[INTEL_FIRMWARE_DIR_ENV]) / file_name
        ).is_file():
            logger.debug(f"{file_name} found in env dir")
            return path

        # When the environment variable is set, don't look elsewhere
        return None

    # Then, look where the firmware download tool writes by default
    if (path := intel_firmware_dir() / file_name).is_file():
        logger.debug(f"{file_name} found in project data dir")
        return path

    # Then, look in the package's driver directory
    if (path := pathlib.Path(__file__).parent / "intel_fw" / file_name).is_file():
        logger.debug(f"{file_name} found in package dir")
        return path

    # On Linux, check the system's FW directory
    if (
        platform.system() == "Linux"
        and (path := pathlib.Path(INTEL_LINUX_FIRMWARE_DIR) / file_name).is_file()
    ):
        logger.debug(f"{file_name} found in Linux system FW dir")
        return path

    # Finally look in the current directory
    if (path := pathlib.Path.cwd() / file_name).is_file():
        logger.debug(f"{file_name} found in CWD")
        return path

    return None


def _parse_tlv(data: bytes) -> list[tuple[ValueType, Any]]:
    result: list[tuple[ValueType, Any]] = []
    while len(data) >= 2:
        value_type = ValueType(data[0])
        value_length = data[1]
        value = data[2 : 2 + value_length]
        typed_value: Any

        if value_type == ValueType.END:
            break

        if value_type in (ValueType.CNVI, ValueType.CNVR):
            (v,) = struct.unpack("<I", value)
            typed_value = (
                (((v >> 0) & 0xF) << 12)
                | (((v >> 4) & 0xF) << 0)
                | (((v >> 8) & 0xF) << 4)
                | (((v >> 24) & 0xF) << 8)
            )
        elif value_type == ValueType.HARDWARE_INFO:
            (v,) = struct.unpack("<I", value)
            typed_value = HardwareInfo(
                HardwarePlatform((v >> 8) & 0xFF), HardwareVariant((v >> 16) & 0x3F)
            )
        elif value_type in (
            ValueType.USB_VENDOR_ID,
            ValueType.USB_PRODUCT_ID,
            ValueType.DEVICE_REVISION,
        ):
            (typed_value,) = struct.unpack("<H", value)
        elif value_type == ValueType.CURRENT_MODE_OF_OPERATION:
            typed_value = ModeOfOperation(value[0])
        elif value_type in (
            ValueType.BUILD_TYPE,
            ValueType.BUILD_NUMBER,
            ValueType.SECURE_BOOT,
            ValueType.OTP_LOCK,
            ValueType.API_LOCK,
            ValueType.DEBUG_LOCK,
            ValueType.SECURE_BOOT_ENGINE_TYPE,
        ):
            typed_value = value[0]
        elif value_type == ValueType.TIMESTAMP:
            typed_value = Timestamp(value[0], value[1])
        elif value_type == ValueType.FIRMWARE_BUILD:
            typed_value = FirmwareBuild(value[0], Timestamp(value[1], value[2]))
        elif value_type == ValueType.BLUETOOTH_ADDRESS:
            typed_value = hci.Address(
                value, address_type=hci.Address.PUBLIC_DEVICE_ADDRESS
            )
        else:
            typed_value = value

        result.append((value_type, typed_value))
        data = data[2 + value_length :]

    return result


# -----------------------------------------------------------------------------
# Classes
# -----------------------------------------------------------------------------
class DriverError(core.BaseBumbleError):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        return f"IntelDriverError({self.message})"


class ValueType(utils.OpenIntEnum):
    END = 0x00
    CNVI = 0x10
    CNVR = 0x11
    HARDWARE_INFO = 0x12
    DEVICE_REVISION = 0x16
    CURRENT_MODE_OF_OPERATION = 0x1C
    USB_VENDOR_ID = 0x17
    USB_PRODUCT_ID = 0x18
    TIMESTAMP = 0x1D
    BUILD_TYPE = 0x1E
    BUILD_NUMBER = 0x1F
    SECURE_BOOT = 0x28
    OTP_LOCK = 0x2A
    API_LOCK = 0x2B
    DEBUG_LOCK = 0x2C
    FIRMWARE_BUILD = 0x2D
    SECURE_BOOT_ENGINE_TYPE = 0x2F
    BLUETOOTH_ADDRESS = 0x30


class HardwarePlatform(utils.OpenIntEnum):
    INTEL_37 = 0x37


class HardwareVariant(utils.OpenIntEnum):
    # This is a just a partial list.
    # Add other constants here as new hardware is encountered and tested.
    TYPHOON_PEAK = 0x17
    GALE_PEAK = 0x1C


@dataclasses.dataclass
class HardwareInfo:
    platform: HardwarePlatform
    variant: HardwareVariant


@dataclasses.dataclass
class Timestamp:
    week: int
    year: int


@dataclasses.dataclass
class FirmwareBuild:
    build_number: int
    timestamp: Timestamp


class ModeOfOperation(utils.OpenIntEnum):
    BOOTLOADER = 0x01
    INTERMEDIATE = 0x02
    OPERATIONAL = 0x03


class SecureBootEngineType(utils.OpenIntEnum):
    RSA = 0x00
    ECDSA = 0x01


@dataclasses.dataclass
class BootParams:
    css_header_offset: int
    css_header_size: int
    pki_offset: int
    pki_size: int
    sig_offset: int
    sig_size: int
    write_offset: int


_BOOT_PARAMS = {
    SecureBootEngineType.RSA: BootParams(0, 128, 128, 256, 388, 256, 964),
    SecureBootEngineType.ECDSA: BootParams(644, 128, 772, 96, 868, 96, 964),
}


class Driver(common.Driver):
    def __init__(self, host: Host) -> None:
        self.host = host
        self.max_in_flight_firmware_load_commands = 1
        self.pending_firmware_load_commands: Deque[hci.HCI_Command] = (
            collections.deque()
        )
        self.can_send_firmware_load_command = asyncio.Event()
        self.can_send_firmware_load_command.set()
        self.firmware_load_complete = asyncio.Event()
        self.reset_complete = asyncio.Event()

        # Parse configuration options from the driver name.
        self.ddc_addon: Optional[bytes] = None
        self.ddc_override: Optional[bytes] = None
        driver = host.hci_metadata.get("driver")
        if driver is not None and driver.startswith("intel/"):
            for key, value in [
                key_eq_value.split(":") for key_eq_value in driver[6:].split("+")
            ]:
                if key == "ddc_addon":
                    self.ddc_addon = bytes.fromhex(value)
                elif key == "ddc_override":
                    self.ddc_override = bytes.fromhex(value)

    @staticmethod
    def check(host: Host) -> bool:
        driver = host.hci_metadata.get("driver")
        if driver == "intel" or driver is not None and driver.startswith("intel/"):
            return True

        vendor_id = host.hci_metadata.get("vendor_id")
        product_id = host.hci_metadata.get("product_id")

        if vendor_id is None or product_id is None:
            logger.debug("USB metadata not sufficient")
            return False

        if (vendor_id, product_id) not in INTEL_USB_PRODUCTS:
            logger.debug(
                f"USB device ({vendor_id:04X}, {product_id:04X}) " "not in known list"
            )
            return False

        return True

    @classmethod
    async def for_host(cls, host: Host, force: bool = False):
        # Only instantiate this driver if explicitly selected
        if not force and not cls.check(host):
            return None

        return cls(host)

    def on_packet(self, packet: bytes) -> None:
        """Handler for event packets that are received from an ACL channel"""
        event = hci.HCI_Event.from_bytes(packet)

        if not isinstance(event, hci.HCI_Command_Complete_Event):
            self.host.on_hci_event_packet(event)
            return

        if not event.return_parameters == hci.HCI_SUCCESS:
            raise DriverError("HCI_Command_Complete_Event error")

        if self.max_in_flight_firmware_load_commands != event.num_hci_command_packets:
            logger.debug(
                "max_in_flight_firmware_load_commands update: "
                f"{event.num_hci_command_packets}"
            )
            self.max_in_flight_firmware_load_commands = event.num_hci_command_packets
        logger.debug(f"event: {event}")
        self.pending_firmware_load_commands.popleft()
        in_flight = len(self.pending_firmware_load_commands)
        logger.debug(f"event received, {in_flight} still in flight")
        if in_flight < self.max_in_flight_firmware_load_commands:
            self.can_send_firmware_load_command.set()

    async def send_firmware_load_command(self, command: hci.HCI_Command) -> None:
        # Wait until we can send.
        await self.can_send_firmware_load_command.wait()

        # Send the command and adjust counters.
        self.host.send_hci_packet(command)
        self.pending_firmware_load_commands.append(command)
        in_flight = len(self.pending_firmware_load_commands)
        if in_flight >= self.max_in_flight_firmware_load_commands:
            logger.debug(f"max commands in flight reached [{in_flight}]")
            self.can_send_firmware_load_command.clear()

    async def send_firmware_data(self, data_type: int, data: bytes) -> None:
        while data:
            fragment_size = min(len(data), _MAX_FRAGMENT_SIZE)
            fragment = data[:fragment_size]
            data = data[fragment_size:]

            await self.send_firmware_load_command(
                Hci_Intel_Secure_Send_Command(data_type=data_type, data=fragment)
            )

    async def load_firmware(self) -> None:
        self.host.ready = True
        device_info = await self.read_device_info()
        logger.debug(
            "device info: \n%s",
            "\n".join(
                [
                    f"  {value_type.name}: {value}"
                    for value_type, value in device_info.items()
                ]
            ),
        )

        # Check if the firmware is already loaded.
        if (
            device_info.get(ValueType.CURRENT_MODE_OF_OPERATION)
            == ModeOfOperation.OPERATIONAL
        ):
            logger.debug("firmware already loaded")
            return

        # We only support some platforms and variants.
        hardware_info = device_info.get(ValueType.HARDWARE_INFO)
        if hardware_info is None:
            raise DriverError("hardware info missing")
        if hardware_info.platform != HardwarePlatform.INTEL_37:
            raise DriverError("hardware platform not supported")
        if hardware_info.variant not in (
            HardwareVariant.TYPHOON_PEAK,
            HardwareVariant.GALE_PEAK,
        ):
            raise DriverError("hardware variant not supported")

        # Compute the firmware name.
        if ValueType.CNVI not in device_info or ValueType.CNVR not in device_info:
            raise DriverError("insufficient device info, missing CNVI or CNVR")

        firmware_base_name = (
            "ibt-"
            f"{device_info[ValueType.CNVI]:04X}-"
            f"{device_info[ValueType.CNVR]:04X}"
        )
        logger.debug(f"FW base name: {firmware_base_name}")

        firmware_name = f"{firmware_base_name}.sfi"
        firmware_path = _find_binary_path(firmware_name)
        if not firmware_path:
            logger.warning(f"Firmware file {firmware_name} not found")
            logger.warning("See https://google.github.io/bumble/drivers/intel.html")
            return None
        logger.debug(f"loading firmware from {firmware_path}")
        firmware_image = firmware_path.read_bytes()

        engine_type = device_info.get(ValueType.SECURE_BOOT_ENGINE_TYPE)
        if engine_type is None:
            raise DriverError("secure boot engine type missing")
        if engine_type not in _BOOT_PARAMS:
            raise DriverError("secure boot engine type not supported")

        boot_params = _BOOT_PARAMS[engine_type]
        if len(firmware_image) < boot_params.write_offset:
            raise DriverError("firmware image too small")

        # Register to receive vendor events.
        def on_vendor_event(event: hci.HCI_Vendor_Event):
            logger.debug(f"vendor event: {event}")
            event_type = event.parameters[0]
            if event_type == 0x02:
                # Boot event
                logger.debug("boot complete")
                self.reset_complete.set()
            elif event_type == 0x06:
                # Firmware load event
                logger.debug("download complete")
                self.firmware_load_complete.set()
            else:
                logger.debug(f"ignoring vendor event type {event_type}")

        self.host.on("vendor_event", on_vendor_event)

        # We need to temporarily intercept packets from the controller,
        # because they are formatted as HCI event packets but are received
        # on the ACL channel, so the host parser would get confused.
        saved_on_packet = self.host.on_packet
        self.host.on_packet = self.on_packet  # type: ignore
        self.firmware_load_complete.clear()

        # Send the CSS header
        data = firmware_image[
            boot_params.css_header_offset : boot_params.css_header_offset
            + boot_params.css_header_size
        ]
        await self.send_firmware_data(0x00, data)

        # Send the PKI header
        data = firmware_image[
            boot_params.pki_offset : boot_params.pki_offset + boot_params.pki_size
        ]
        await self.send_firmware_data(0x03, data)

        # Send the Signature header
        data = firmware_image[
            boot_params.sig_offset : boot_params.sig_offset + boot_params.sig_size
        ]
        await self.send_firmware_data(0x02, data)

        # Send the rest of the image.
        # The payload consists of command objects, which are sent when they add up
        # to a multiple of 4 bytes.
        boot_address = 0
        offset = boot_params.write_offset
        fragment_size = 0
        while offset + 3 < len(firmware_image):
            (command_opcode,) = struct.unpack_from(
                "<H", firmware_image, offset + fragment_size
            )
            command_size = firmware_image[offset + fragment_size + 2]
            if command_opcode == HCI_INTEL_WRITE_BOOT_PARAMS_COMMAND:
                (boot_address,) = struct.unpack_from(
                    "<I", firmware_image, offset + fragment_size + 3
                )
                logger.debug(
                    "found HCI_INTEL_WRITE_BOOT_PARAMS_COMMAND, "
                    f"boot_address={boot_address}"
                )
            fragment_size += 3 + command_size
            if fragment_size % 4 == 0:
                await self.send_firmware_data(
                    0x01, firmware_image[offset : offset + fragment_size]
                )
                logger.debug(f"sent {fragment_size} bytes")
                offset += fragment_size
                fragment_size = 0

        # Wait for the firmware loading to be complete.
        logger.debug("waiting for firmware to be loaded")
        await self.firmware_load_complete.wait()
        logger.debug("firmware loaded")

        # Restore the original packet handler.
        self.host.on_packet = saved_on_packet  # type: ignore

        # Reset
        self.reset_complete.clear()
        self.host.send_hci_packet(
            HCI_Intel_Reset_Command(
                reset_type=0x00,
                patch_enable=0x01,
                ddc_reload=0x00,
                boot_option=0x01,
                boot_address=boot_address,
            )
        )
        logger.debug("waiting for reset completion")
        await self.reset_complete.wait()
        logger.debug("reset complete")

        # Load the device config if there is one.
        if self.ddc_override:
            logger.debug("loading overridden DDC")
            await self.load_device_config(self.ddc_override)
        else:
            ddc_name = f"{firmware_base_name}.ddc"
            ddc_path = _find_binary_path(ddc_name)
            if ddc_path:
                logger.debug(f"loading DDC from {ddc_path}")
                ddc_data = ddc_path.read_bytes()
                await self.load_device_config(ddc_data)
        if self.ddc_addon:
            logger.debug("loading DDC addon")
            await self.load_device_config(self.ddc_addon)

    async def load_device_config(self, ddc_data: bytes) -> None:
        while ddc_data:
            ddc_len = 1 + ddc_data[0]
            ddc_payload = ddc_data[:ddc_len]
            await self.host.send_command(
                Hci_Intel_Write_Device_Config_Command(data=ddc_payload)
            )
            ddc_data = ddc_data[ddc_len:]

    async def reboot_bootloader(self) -> None:
        self.host.send_hci_packet(
            HCI_Intel_Reset_Command(
                reset_type=0x01,
                patch_enable=0x01,
                ddc_reload=0x01,
                boot_option=0x00,
                boot_address=0,
            )
        )
        await asyncio.sleep(_POST_RESET_DELAY)

    async def read_device_info(self) -> dict[ValueType, Any]:
        self.host.ready = True
        response = await self.host.send_command(hci.HCI_Reset_Command())
        if not (
            isinstance(response, hci.HCI_Command_Complete_Event)
            and response.return_parameters
            in (hci.HCI_UNKNOWN_HCI_COMMAND_ERROR, hci.HCI_SUCCESS)
        ):
            # When the controller is in operational mode, the response is a
            # successful response.
            # When the controller is in bootloader mode,
            # HCI_UNKNOWN_HCI_COMMAND_ERROR is the expected response. Anything
            # else is a failure.
            logger.warning(f"unexpected response: {response}")
            raise DriverError("unexpected HCI response")

        # Read the firmware version.
        response = await self.host.send_command(
            HCI_Intel_Read_Version_Command(param0=0xFF)
        )
        if not isinstance(response, hci.HCI_Command_Complete_Event):
            raise DriverError("unexpected HCI response")

        if response.return_parameters.status != 0:  # type: ignore
            raise DriverError("HCI_Intel_Read_Version_Command error")

        tlvs = _parse_tlv(response.return_parameters.tlv)  # type: ignore

        # Convert the list to a dict. That's Ok here because we only expect each type
        # to appear just once.
        return dict(tlvs)

    async def init_controller(self):
        await self.load_firmware()
