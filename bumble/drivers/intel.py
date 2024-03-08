# Copyright 2021-2023 Google LLC
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
Support for Intel AX210 controllers.
Based on the Linux kernel implementation.
(see `drivers/bluetooth/btintel.c`)
"""

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import asyncio
from dataclasses import dataclass
from enum import IntEnum
import logging
import os
import pathlib
import platform
from typing import Optional, Tuple

from bumble.hci import (
    hci_vendor_command_op_code,  # type: ignore
    HCI_Command,
    HCI_Reset_Command,
    STATUS_SPEC,  # type: ignore
    HCI_SUCCESS,
)
from bumble.drivers import common

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
CSS_HEADER_OFFSET = 8
ECDSA_OFFSET = 644
OPERATIONAL_FW = 0x03
INTEL_VENDOR_ID = 0x0000
HW_PLATFORM = 0x37
MAX_FRAGMENT_PAYLOAD = 252
RSA_HEADER_LEN = 644
ECDSA_HEADER_LEN = 320

HCI_CMD_WRITE_BOOT_PARAMS = 0xFC0E

INTEL_FIRMWARE_DIR_ENV = "BUMBLE_INTEL_FIRMWARE_DIR"
LINUX_FIRMWARE_PATH = "/lib/firmware/intel/"


class TLV(IntEnum):
    CNVI_TOP = 0x10
    CNVR_TOP = 0x11
    CNVI_BT = 0x12
    IMG_TYPE = 0x1C
    SBE_TYPE = 0x2F


@dataclass
class IntelVersionTLV:
    cnvi_top: Optional[bytes] = None
    cnvr_top: Optional[bytes] = None
    cnvi_bt: Optional[bytes] = None
    img_type: Optional[bytes] = None
    sbe_type: Optional[bytes] = None


class TLVType(IntEnum):
    CNVI_TOP = 0x10
    CNVR_TOP = 0x11
    CNVI_BT = 0x12
    IMG_TYPE = 0x1C
    SBE_TYPE = 0x2F


def parse_intel_version_tlvs(data: bytes, offset: int) -> IntelVersionTLV:
    new_offset = len(data)
    data = data[offset:]

    if data[0] == 0x37:
        raise ValueError("Legacy Intel version tlv")

    tlvs = {}
    while len(data) > 0:
        try:
            tlv_type = data[0]
            tlv_length = data[1]
            tlv_value = data[2 : 2 + tlv_length]

            try:
                tlvs[TLVType(tlv_type).name.lower()] = tlv_value
            except ValueError:
                pass  # unknown tlv

            data = data[2 + tlv_length :]
        except IndexError:
            logging.error("TLV parse error")
            continue

    return new_offset, IntelVersionTLV(**tlvs)  # type: ignore


# -----------------------------------------------------------------------------
# HCI Commands
# -----------------------------------------------------------------------------
HCI_INTEL_READ_VERSION_COMMAND = hci_vendor_command_op_code(0xFC05)  # type: ignore
HCI_INTEL_SECURE_SEND_COMMAND = hci_vendor_command_op_code(0xFC09)  # type: ignore
HCI_INTEL_RESET_COMMAND = hci_vendor_command_op_code(0xFC01)  # type: ignore
HCI_INTEL_DDC_CONFIG_WRITE_COMMAND = hci_vendor_command_op_code(0xFC8B)  # type: ignore
HCI_Command.register_commands(globals())

HCI_INTEL_DDC_CONFIG_WRITE_PAYLOAD = [0x03, 0xE4, 0x02, 0x00]


@HCI_Command.command(  # type: ignore
    fields=[("param", 1)],
    return_parameters_fields=[
        ("status", STATUS_SPEC),
        ("version", parse_intel_version_tlvs),
    ],
)
class HCI_Intel_Read_Version_Command(HCI_Command):
    pass


@HCI_Command.command(  # type: ignore
    fields=[("param", "*")],
    return_parameters_fields=[
        ("status", STATUS_SPEC),
    ],
)
class Hci_Intel_Secure_Send_Command(HCI_Command):
    pass


@HCI_Command.command(  # type: ignore
    fields=[("params", "*")],
    return_parameters_fields=[
        ("params", "*"),
    ],
)
class Hci_Intel_DDC_Config_Write_Command(HCI_Command):
    pass


# Please see linux/drivers/bluetooth/btintel.c for more informations.
# Intel Reset parameter description:
# reset_type : 0x00 (Soft reset), 0x01 (Hard reset)
# patch_enable: 0x00 (Do not enable), 0x01 (Enable)
# ddc_reload : 0x00 (Do not reload),  0x01 (Reload)
# boot_option: 0x00 (Current image), 0x01 (Specified boot address)
# boot_param: Boot address
@HCI_Command.command(  # type: ignore
    fields=[
        ("reset_type", 1),
        ("patch_enable", 1),
        ("ddc_reload", 1),
        ("boot_option", 1),
        ("boot_param", 4),
    ],
    return_parameters_fields=[
        ("data", "*"),
    ],
)
class Hci_Intel_Reset_Command(HCI_Command):
    pass


# -----------------------------------------------------------------------------


async def secure_send(host, fragment_type: int, plen: int, param: bytes):
    while plen > 0:
        fragment_len = MAX_FRAGMENT_PAYLOAD if plen > MAX_FRAGMENT_PAYLOAD else plen
        cmd_param = bytes([fragment_type]) + param[:fragment_len]

        # await host.send_command(Hci_Intel_Secure_Send_Command(param=cmd_param))  # type: ignore
        host.send_hci_packet(Hci_Intel_Secure_Send_Command(param=cmd_param))  # type: ignore
        await asyncio.sleep(0.002)

        plen -= fragment_len
        param = param[fragment_len:]


async def sfi_ecdsa_header_secure_send(host, fw: bytes):
    try:
        # Start the firmware download transaction with the Init fragment
        # represented by the 128 bytes of CSS header.
        await secure_send(host, 0x00, 128, fw[ECDSA_OFFSET:])
    except IOError as e:
        logging.error(f"Failed to send fw header: {e}")
        return

    try:
        # Send the 256 bytes of public key information from the fw
        pkey_offset = ECDSA_OFFSET + 128
        await secure_send(host, 0x03, 96, fw[pkey_offset:])
    except IOError as e:
        logger.error(f"Failed to send firmware pkey: {e}")
        return

    try:
        sign_offset = ECDSA_OFFSET + 224
        await secure_send(host, 0x02, 96, fw[sign_offset:])
    except IOError as e:
        logger.error(f"Failed to send firmware signature: {e}")
        return


def fetch_boot_addr(fw: bytes) -> Tuple[int, str]:  # tuple[boot_addr, fw_version]
    while len(fw) > 0:
        length = 3 + fw[2]
        op_code = int.from_bytes(fw[:2], byteorder='little')
        if op_code == HCI_CMD_WRITE_BOOT_PARAMS:
            boot_addr = int.from_bytes(fw[3:7], byteorder='little')
            fw_build_num = fw[7]
            fw_build_week = fw[8]
            fw_build_year = fw[9]
            fw_version = f"{fw_build_num}-{fw_build_week}.{fw_build_year}"
            return (boot_addr, fw_version)
        fw = fw[length:]
    return (0, "")  # todo: handle error


async def download_fw_payload(host, fw: bytes, header_offset: int):
    payload_data = fw[header_offset:]  # possiblement boot_data est dans le header
    frag_len = 0

    while len(payload_data) > 0:
        frag_len += 3 + payload_data[frag_len + 2]

        if frag_len % 4 == 0:
            await secure_send(host, 0x01, frag_len, payload_data)
            payload_data = payload_data[frag_len:]
            frag_len = 0


async def reboot_bootloader(host):  # type: ignore
    host.send_command_sync(  # type: ignore
        Hci_Intel_Reset_Command(
            reset_type=0x01,
            patch_enable=0x01,
            ddc_reload=0x01,
            boot_option=0x00,
            boot_param=0x00000000,
        )
    )

    await asyncio.sleep(200 / 1000)


class Driver(common.Driver):
    def __init__(self, host, version: IntelVersionTLV, firmware: bytes, fw_name: str):
        self.host = host
        self.version = version
        self.firmware = firmware
        self.fw_name = fw_name

    @classmethod
    async def for_host(cls, host, force=False):  # type: ignore
        try:
            if not force and not cls.check(host):
                return None

            version = await fetch_intel_version(host)  # type: ignore
            fw, fw_name = prepare_firmware(version)
            return cls(host, version, fw, fw_name)
        except Exception:
            logging.exception("Error preparing the firmware")
            return None

    async def init_controller(self):
        try:
            await download_firmware(self.host, self.version, self.firmware)
            await self.host.send_command(HCI_Reset_Command(), check_result=True)
            # Enable host-initiated role-switching
            await self.host.send_command(
                Hci_Intel_DDC_Config_Write_Command(
                    params=HCI_INTEL_DDC_CONFIG_WRITE_PAYLOAD
                )
            )
            logger.info(f"Firmware loaded, image: {self.fw_name}")
        except Exception:
            logging.exception("Failed to download the firmware")
            return None

    @staticmethod
    def check(host):
        if host.hci_metadata.get('driver') == 'intel':
            # Forced driver
            return True

    @staticmethod
    def find_binary_path(file_name: str) -> Optional[pathlib.Path]:
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
            and (path := pathlib.Path(LINUX_FIRMWARE_PATH) / file_name).is_file()
        ):
            logger.debug(f"{file_name} found in Linux system FW dir")
            return path

        # Finally look in the current directory
        if (path := pathlib.Path.cwd() / file_name).is_file():
            logger.debug(f"{file_name} found in CWD")
            return path

        return None

    @classmethod
    async def driver_info_for_host(cls, host) -> str:
        version = await fetch_intel_version(host)
        fw_name = fetch_firmware_name(version)
        return fw_name


async def fetch_intel_version(host) -> IntelVersionTLV:  # type: ignore
    host.ready = True  # Needed to let the host know the controller is ready.
    response = await host.send_command(HCI_Intel_Read_Version_Command(param=0xFF), check_result=True)  # type: ignore
    if response.return_parameters.status != HCI_SUCCESS:  # type: ignore
        raise ValueError("This controller is not an intel device")

    intel_version_tlvs = response.return_parameters.version  # type: ignore

    assert isinstance(intel_version_tlvs, IntelVersionTLV)

    if intel_version_tlvs.cnvi_bt is None:
        raise ValueError("CNVI_BT cannot be None")

    intel_hw_platform = intel_version_tlvs.cnvi_bt[1]
    if intel_hw_platform != HW_PLATFORM:
        raise ValueError("Unsupported Intel hardware platform")

    intel_hw_variant = (
        int.from_bytes(intel_version_tlvs.cnvi_bt, 'little') & 0x003F0000
    ) >> 16
    if intel_hw_variant in [0x17, 0x18, 0x19, 0x1B, 0x1C]:
        return intel_version_tlvs
    else:
        raise ValueError("Unsupported Intel hardware variant")


def intel_cnvx_top_pack_swab(top: int, step: int) -> int:
    combined: int = ((top << 4) | step) & 0xFFFF

    return ((combined >> 8) & 0xFF) | ((combined & 0xFF) << 8)


def fetch_firmware_name(version: IntelVersionTLV) -> str:
    if version.cnvi_top is None or version.cnvr_top is None:
        raise ValueError("cnvi_top and cnvr_top cannot be None")

    cnvi_top = int.from_bytes(version.cnvi_top, byteorder='little')
    cnvi_top_step = (cnvi_top & 0x0F000000) >> 24  # type: ignore
    cnvi_top_type = cnvi_top & 0x00000FFF

    cnvr_top = int.from_bytes(version.cnvr_top, byteorder='little')
    cnvr_top_step = (cnvr_top & 0x0F000000) >> 24
    cnvr_top_type = cnvr_top & 0x00000FFF

    upper_name = intel_cnvx_top_pack_swab(cnvi_top_type, cnvi_top_step)
    lower_name = intel_cnvx_top_pack_swab(cnvr_top_type, cnvr_top_step)

    return f"ibt-{upper_name:04x}-{lower_name:04x}.sfi"


def prepare_firmware(version: IntelVersionTLV) -> Tuple[bytes, str]:
    fw_name = fetch_firmware_name(version)
    logging.debug(f"Firmware: {fw_name}")
    fw_path = Driver.find_binary_path(fw_name)
    if not fw_path:
        raise FileNotFoundError(f"Firmware file {fw_name} not found")
    with open(fw_path, 'rb') as fw_file:
        fw = fw_file.read()
        if len(fw) < 644:
            raise ValueError(
                "Firmware size is less then the minimum required size of 644 bytes"
            )
        return (fw, fw_name)


async def download_firmware(host, version: IntelVersionTLV, fw: bytes):
    if version.img_type is None:
        raise ValueError("IMG_TYPE cannot be NONE")

    if version.img_type[0] == OPERATIONAL_FW:
        raise RuntimeError(
            "Device needs to be reset to bootloader. See tools/intel_utils.py --help."
        )

    if version.cnvi_bt is None:
        raise ValueError("CNVI Bluetooth verion cannot be None")
    hw_variant = (int.from_bytes(version.cnvi_bt, 'little') & 0x003F0000) >> 16

    if hw_variant >= 0x17:
        if fw[ECDSA_OFFSET] != 0x06:
            raise ValueError("Invalid CSS header")
        css_header_version = int.from_bytes(
            fw[ECDSA_OFFSET + CSS_HEADER_OFFSET :][:4], byteorder='little'
        )
        if css_header_version != 0x00020000:
            raise ValueError("Invalid CSS Header version")

    if version.sbe_type is None:
        raise ValueError("SBE_TYPE cannot be none")
    sbe_type = int.from_bytes(version.sbe_type, byteorder='little')
    (boot_addr, fw_version) = fetch_boot_addr(fw)
    logging.info(f"Boot addr: {hex(boot_addr)}")
    logging.info(f"Firmware version: {fw_version}")
    if sbe_type == 0x01:
        await sfi_ecdsa_header_secure_send(host, fw)
        await download_fw_payload(host, fw, RSA_HEADER_LEN + ECDSA_HEADER_LEN)
        await host.send_command(  # type: ignore
            Hci_Intel_Reset_Command(
                reset_type=0x00,
                patch_enable=0x01,
                ddc_reload=0x00,
                boot_option=0x01,
                boot_param=boot_addr,
            )
        )
        await asyncio.sleep(2)
    else:
        raise ValueError("SBE_TYPE != 0x01 is unsupported")


def intel_firmware_dir() -> pathlib.Path:
    """
    Returns:
        A path to a subdir of the project data dir for Realtek firmware.
         The directory is created if it doesn't exist.
    """
    from bumble.drivers import project_data_dir

    p = project_data_dir() / "firmware" / "intel"
    p.mkdir(parents=True, exist_ok=True)
    return p
