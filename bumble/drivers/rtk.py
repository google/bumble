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
Support for Realtek USB dongles.
Based on various online bits of information, including the Linux kernel.
(see `drivers/bluetooth/btrtl.c`)
"""

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from dataclasses import dataclass
import asyncio
import enum
import logging
import math
import os
import pathlib
import platform
import struct
from typing import Tuple
import weakref


from bumble.hci import (
    hci_vendor_command_op_code,
    STATUS_SPEC,
    HCI_SUCCESS,
    HCI_Command,
    HCI_Reset_Command,
    HCI_Read_Local_Version_Information_Command,
)


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
RTK_ROM_LMP_8723A = 0x1200
RTK_ROM_LMP_8723B = 0x8723
RTK_ROM_LMP_8821A = 0x8821
RTK_ROM_LMP_8761A = 0x8761
RTK_ROM_LMP_8822B = 0x8822
RTK_ROM_LMP_8852A = 0x8852
RTK_CONFIG_MAGIC = 0x8723AB55

RTK_EPATCH_SIGNATURE = b"Realtech"

RTK_FRAGMENT_LENGTH = 252

RTK_FIRMWARE_DIR_ENV = "BUMBLE_RTK_FIRMWARE_DIR"
RTK_LINUX_FIRMWARE_DIR = "/lib/firmware/rtl_bt"


class RtlProjectId(enum.IntEnum):
    PROJECT_ID_8723A = 0
    PROJECT_ID_8723B = 1
    PROJECT_ID_8821A = 2
    PROJECT_ID_8761A = 3
    PROJECT_ID_8822B = 8
    PROJECT_ID_8723D = 9
    PROJECT_ID_8821C = 10
    PROJECT_ID_8822C = 13
    PROJECT_ID_8761B = 14
    PROJECT_ID_8852A = 18
    PROJECT_ID_8852B = 20
    PROJECT_ID_8852C = 25


RTK_PROJECT_ID_TO_ROM = {
    0: RTK_ROM_LMP_8723A,
    1: RTK_ROM_LMP_8723B,
    2: RTK_ROM_LMP_8821A,
    3: RTK_ROM_LMP_8761A,
    8: RTK_ROM_LMP_8822B,
    9: RTK_ROM_LMP_8723B,
    10: RTK_ROM_LMP_8821A,
    13: RTK_ROM_LMP_8822B,
    14: RTK_ROM_LMP_8761A,
    18: RTK_ROM_LMP_8852A,
    20: RTK_ROM_LMP_8852A,
    25: RTK_ROM_LMP_8852A,
}

# List of USB (VendorID, ProductID) for Realtek-based devices.
RTK_USB_PRODUCTS = {
    # Realtek 8723AE
    (0x0930, 0x021D),
    (0x13D3, 0x3394),
    # Realtek 8723BE
    (0x0489, 0xE085),
    (0x0489, 0xE08B),
    (0x04F2, 0xB49F),
    (0x13D3, 0x3410),
    (0x13D3, 0x3416),
    (0x13D3, 0x3459),
    (0x13D3, 0x3494),
    # Realtek 8723BU
    (0x7392, 0xA611),
    # Realtek 8723DE
    (0x0BDA, 0xB009),
    (0x2FF8, 0xB011),
    # Realtek 8761BUV
    (0x0B05, 0x190E),
    (0x0BDA, 0x8771),
    (0x2230, 0x0016),
    (0x2357, 0x0604),
    (0x2550, 0x8761),
    (0x2B89, 0x8761),
    (0x7392, 0xC611),
    (0x0BDA, 0x877B),
    # Realtek 8821AE
    (0x0B05, 0x17DC),
    (0x13D3, 0x3414),
    (0x13D3, 0x3458),
    (0x13D3, 0x3461),
    (0x13D3, 0x3462),
    # Realtek 8821CE
    (0x0BDA, 0xB00C),
    (0x0BDA, 0xC822),
    (0x13D3, 0x3529),
    # Realtek 8822BE
    (0x0B05, 0x185C),
    (0x13D3, 0x3526),
    # Realtek 8822CE
    (0x04C5, 0x161F),
    (0x04CA, 0x4005),
    (0x0B05, 0x18EF),
    (0x0BDA, 0xB00C),
    (0x0BDA, 0xC123),
    (0x0BDA, 0xC822),
    (0x0CB5, 0xC547),
    (0x1358, 0xC123),
    (0x13D3, 0x3548),
    (0x13D3, 0x3549),
    (0x13D3, 0x3553),
    (0x13D3, 0x3555),
    (0x2FF8, 0x3051),
    # Realtek 8822CU
    (0x13D3, 0x3549),
    # Realtek 8852AE
    (0x04C5, 0x165C),
    (0x04CA, 0x4006),
    (0x0BDA, 0x2852),
    (0x0BDA, 0x385A),
    (0x0BDA, 0x4852),
    (0x0BDA, 0xC852),
    (0x0CB8, 0xC549),
    # Realtek 8852BE
    (0x0BDA, 0x887B),
    (0x0CB8, 0xC559),
    (0x13D3, 0x3571),
    # Realtek 8852CE
    (0x04C5, 0x1675),
    (0x04CA, 0x4007),
    (0x0CB8, 0xC558),
    (0x13D3, 0x3586),
    (0x13D3, 0x3587),
    (0x13D3, 0x3592),
}

# -----------------------------------------------------------------------------
# HCI Commands
# -----------------------------------------------------------------------------
HCI_RTK_READ_ROM_VERSION_COMMAND = hci_vendor_command_op_code(0x6D)
HCI_RTK_DOWNLOAD_COMMAND = hci_vendor_command_op_code(0x20)
HCI_RTK_DROP_FIRMWARE_COMMAND = hci_vendor_command_op_code(0x66)
HCI_Command.register_commands(globals())


@HCI_Command.command(return_parameters_fields=[("status", STATUS_SPEC), ("version", 1)])
class HCI_RTK_Read_ROM_Version_Command(HCI_Command):
    pass


@HCI_Command.command(
    fields=[("index", 1), ("payload", RTK_FRAGMENT_LENGTH)],
    return_parameters_fields=[("status", STATUS_SPEC), ("index", 1)],
)
class HCI_RTK_Download_Command(HCI_Command):
    pass


@HCI_Command.command()
class HCI_RTK_Drop_Firmware_Command(HCI_Command):
    pass


# -----------------------------------------------------------------------------
class Firmware:
    def __init__(self, firmware):
        extension_sig = bytes([0x51, 0x04, 0xFD, 0x77])

        if not firmware.startswith(RTK_EPATCH_SIGNATURE):
            raise ValueError("Firmware does not start with epatch signature")

        if not firmware.endswith(extension_sig):
            raise ValueError("Firmware does not end with extension sig")

        # The firmware should start with a 14 byte header.
        epatch_header_size = 14
        if len(firmware) < epatch_header_size:
            raise ValueError("Firmware too short")

        # Look for the "project ID", starting from the end.
        offset = len(firmware) - len(extension_sig)
        project_id = -1
        while offset >= epatch_header_size:
            length, opcode = firmware[offset - 2 : offset]
            offset -= 2

            if opcode == 0xFF:
                # End
                break

            if length == 0:
                raise ValueError("Invalid 0-length instruction")

            if opcode == 0 and length == 1:
                project_id = firmware[offset - 1]
                break

            offset -= length

        if project_id < 0:
            raise ValueError("Project ID not found")

        self.project_id = project_id

        # Read the patch tables info.
        self.version, num_patches = struct.unpack("<IH", firmware[8:14])
        self.patches = []

        # The patches tables are laid out as:
        # <ChipID_1><ChipID_2>...<ChipID_N>  (16 bits each)
        # <PatchLength_1><PatchLength_2>...<PatchLength_N> (16 bits each)
        # <PatchOffset_1><PatchOffset_2>...<PatchOffset_N> (32 bits each)
        if epatch_header_size + 8 * num_patches > len(firmware):
            raise ValueError("Firmware too short")
        chip_id_table_offset = epatch_header_size
        patch_length_table_offset = chip_id_table_offset + 2 * num_patches
        patch_offset_table_offset = chip_id_table_offset + 4 * num_patches
        for patch_index in range(num_patches):
            chip_id_offset = chip_id_table_offset + 2 * patch_index
            (chip_id,) = struct.unpack_from("<H", firmware, chip_id_offset)
            (patch_length,) = struct.unpack_from(
                "<H", firmware, patch_length_table_offset + 2 * patch_index
            )
            (patch_offset,) = struct.unpack_from(
                "<I", firmware, patch_offset_table_offset + 4 * patch_index
            )
            if patch_offset + patch_length > len(firmware):
                raise ValueError("Firmware too short")

            # Get the SVN version for the patch
            (svn_version,) = struct.unpack_from(
                "<I", firmware, patch_offset + patch_length - 8
            )

            # Create a payload with the patch, replacing the last 4 bytes with
            # the firmware version.
            self.patches.append(
                (
                    chip_id,
                    firmware[patch_offset : patch_offset + patch_length - 4]
                    + struct.pack("<I", self.version),
                    svn_version,
                )
            )


class Driver:
    @dataclass
    class DriverInfo:
        rom: int
        hci: Tuple[int, int]
        config_needed: bool
        has_rom_version: bool
        has_msft_ext: bool = False
        fw_name: str = ""
        config_name: str = ""

    DRIVER_INFOS = [
        # 8723A
        DriverInfo(
            rom=RTK_ROM_LMP_8723A,
            hci=(0x0B, 0x06),
            config_needed=False,
            has_rom_version=False,
            fw_name="rtl8723a_fw.bin",
            config_name="",
        ),
        # 8723B
        DriverInfo(
            rom=RTK_ROM_LMP_8723B,
            hci=(0x0B, 0x06),
            config_needed=False,
            has_rom_version=True,
            fw_name="rtl8723b_fw.bin",
            config_name="rtl8723b_config.bin",
        ),
        # 8723D
        DriverInfo(
            rom=RTK_ROM_LMP_8723B,
            hci=(0x0D, 0x08),
            config_needed=True,
            has_rom_version=True,
            fw_name="rtl8723d_fw.bin",
            config_name="rtl8723d_config.bin",
        ),
        # 8821A
        DriverInfo(
            rom=RTK_ROM_LMP_8821A,
            hci=(0x0A, 0x06),
            config_needed=False,
            has_rom_version=True,
            fw_name="rtl8821a_fw.bin",
            config_name="rtl8821a_config.bin",
        ),
        # 8821C
        DriverInfo(
            rom=RTK_ROM_LMP_8821A,
            hci=(0x0C, 0x08),
            config_needed=False,
            has_rom_version=True,
            has_msft_ext=True,
            fw_name="rtl8821c_fw.bin",
            config_name="rtl8821c_config.bin",
        ),
        # 8761A
        DriverInfo(
            rom=RTK_ROM_LMP_8761A,
            hci=(0x0A, 0x06),
            config_needed=False,
            has_rom_version=True,
            fw_name="rtl8761a_fw.bin",
            config_name="rtl8761a_config.bin",
        ),
        # 8761BU
        DriverInfo(
            rom=RTK_ROM_LMP_8761A,
            hci=(0x0B, 0x0A),
            config_needed=False,
            has_rom_version=True,
            fw_name="rtl8761bu_fw.bin",
            config_name="rtl8761bu_config.bin",
        ),
        # 8822C
        DriverInfo(
            rom=RTK_ROM_LMP_8822B,
            hci=(0x0C, 0x0A),
            config_needed=False,
            has_rom_version=True,
            has_msft_ext=True,
            fw_name="rtl8822cu_fw.bin",
            config_name="rtl8822cu_config.bin",
        ),
        # 8822B
        DriverInfo(
            rom=RTK_ROM_LMP_8822B,
            hci=(0x0B, 0x07),
            config_needed=True,
            has_rom_version=True,
            has_msft_ext=True,
            fw_name="rtl8822b_fw.bin",
            config_name="rtl8822b_config.bin",
        ),
        # 8852A
        DriverInfo(
            rom=RTK_ROM_LMP_8852A,
            hci=(0x0A, 0x0B),
            config_needed=False,
            has_rom_version=True,
            has_msft_ext=True,
            fw_name="rtl8852au_fw.bin",
            config_name="rtl8852au_config.bin",
        ),
        # 8852B
        DriverInfo(
            rom=RTK_ROM_LMP_8852A,
            hci=(0xB, 0xB),
            config_needed=False,
            has_rom_version=True,
            has_msft_ext=True,
            fw_name="rtl8852bu_fw.bin",
            config_name="rtl8852bu_config.bin",
        ),
        # 8852C
        DriverInfo(
            rom=RTK_ROM_LMP_8852A,
            hci=(0x0C, 0x0C),
            config_needed=False,
            has_rom_version=True,
            has_msft_ext=True,
            fw_name="rtl8852cu_fw.bin",
            config_name="rtl8852cu_config.bin",
        ),
    ]

    POST_DROP_DELAY = 0.2

    @staticmethod
    def find_driver_info(hci_version, hci_subversion, lmp_subversion):
        for driver_info in Driver.DRIVER_INFOS:
            if driver_info.rom == lmp_subversion and driver_info.hci == (
                hci_subversion,
                hci_version,
            ):
                return driver_info

        return None

    @staticmethod
    def find_binary_path(file_name):
        # First check if an environment variable is set
        if RTK_FIRMWARE_DIR_ENV in os.environ:
            if (
                path := pathlib.Path(os.environ[RTK_FIRMWARE_DIR_ENV]) / file_name
            ).is_file():
                logger.debug(f"{file_name} found in env dir")
                return path

            # When the environment variable is set, don't look elsewhere
            return None

        # Then, look where the firmware download tool writes by default
        if (path := rtk_firmware_dir() / file_name).is_file():
            logger.debug(f"{file_name} found in project data dir")
            return path

        # Then, look in the package's driver directory
        if (path := pathlib.Path(__file__).parent / "rtk_fw" / file_name).is_file():
            logger.debug(f"{file_name} found in package dir")
            return path

        # On Linux, check the system's FW directory
        if (
            platform.system() == "Linux"
            and (path := pathlib.Path(RTK_LINUX_FIRMWARE_DIR) / file_name).is_file()
        ):
            logger.debug(f"{file_name} found in Linux system FW dir")
            return path

        # Finally look in the current directory
        if (path := pathlib.Path.cwd() / file_name).is_file():
            logger.debug(f"{file_name} found in CWD")
            return path

        return None

    @staticmethod
    def check(host):
        if not host.hci_metadata:
            logger.debug("USB metadata not found")
            return False

        vendor_id = host.hci_metadata.get("vendor_id", None)
        product_id = host.hci_metadata.get("product_id", None)
        if vendor_id is None or product_id is None:
            logger.debug("USB metadata not sufficient")
            return False

        if (vendor_id, product_id) not in RTK_USB_PRODUCTS:
            logger.debug(
                f"USB device ({vendor_id:04X}, {product_id:04X}) " "not in known list"
            )
            return False

        return True

    @classmethod
    async def driver_info_for_host(cls, host):
        response = await host.send_command(
            HCI_Read_Local_Version_Information_Command(), check_result=True
        )
        local_version = response.return_parameters

        logger.debug(
            f"looking for a driver: 0x{local_version.lmp_subversion:04X} "
            f"(0x{local_version.hci_version:02X}, "
            f"0x{local_version.hci_subversion:04X})"
        )

        driver_info = cls.find_driver_info(
            local_version.hci_version,
            local_version.hci_subversion,
            local_version.lmp_subversion,
        )
        if driver_info is None:
            # TODO: it seems that the Linux driver will send command (0x3f, 0x66)
            # in this case and then re-read the local version, then re-match.
            logger.debug("firmware already loaded or no known driver for this device")

        return driver_info

    @classmethod
    async def for_host(cls, host, force=False):
        # Check that a driver is needed for this host
        if not force and not cls.check(host):
            return None

        # Get the driver info
        driver_info = await cls.driver_info_for_host(host)
        if driver_info is None:
            return None

        # Load the firmware
        firmware_path = cls.find_binary_path(driver_info.fw_name)
        if not firmware_path:
            logger.warning(f"Firmware file {driver_info.fw_name} not found")
            logger.warning("See https://google.github.io/bumble/drivers/realtek.html")
            return None
        with open(firmware_path, "rb") as firmware_file:
            firmware = firmware_file.read()

        # Load the config
        config = None
        if driver_info.config_name:
            config_path = cls.find_binary_path(driver_info.config_name)
            if config_path:
                with open(config_path, "rb") as config_file:
                    config = config_file.read()
        if driver_info.config_needed and not config:
            logger.warning("Config needed, but no config file available")
            return None

        return cls(host, driver_info, firmware, config)

    def __init__(self, host, driver_info, firmware, config):
        self.host = weakref.proxy(host)
        self.driver_info = driver_info
        self.firmware = firmware
        self.config = config

    @staticmethod
    async def drop_firmware(host):
        host.send_hci_packet(HCI_RTK_Drop_Firmware_Command())

        # Wait for the command to be effective (no response is sent)
        await asyncio.sleep(Driver.POST_DROP_DELAY)

    async def download_for_rtl8723a(self):
        # Check that the firmware image does not include an epatch signature.
        if RTK_EPATCH_SIGNATURE in self.firmware:
            logger.warning(
                "epatch signature found in firmware, it is probably the wrong firmware"
            )
            return

        # TODO: load the firmware

    async def download_for_rtl8723b(self):
        if self.driver_info.has_rom_version:
            response = await self.host.send_command(
                HCI_RTK_Read_ROM_Version_Command(), check_result=True
            )
            if response.return_parameters.status != HCI_SUCCESS:
                logger.warning("can't get ROM version")
                return
            rom_version = response.return_parameters.version
            logger.debug(f"ROM version before download: {rom_version:04X}")
        else:
            rom_version = 0

        firmware = Firmware(self.firmware)
        logger.debug(f"firmware: project_id=0x{firmware.project_id:04X}")
        for patch in firmware.patches:
            if patch[0] == rom_version + 1:
                logger.debug(f"using patch {patch[0]}")
                break
        else:
            logger.warning("no valid patch found for rom version {rom_version}")
            return

        # Append the config if there is one.
        if self.config:
            payload = patch[1] + self.config
        else:
            payload = patch[1]

        # Download the payload, one fragment at a time.
        fragment_count = math.ceil(len(payload) / RTK_FRAGMENT_LENGTH)
        for fragment_index in range(fragment_count):
            # NOTE: the Linux driver somehow adds 1 to the index after it wraps around.
            # That's odd, but we"ll do the same here.
            download_index = fragment_index & 0x7F
            if download_index >= 0x80:
                download_index += 1
            if fragment_index == fragment_count - 1:
                download_index |= 0x80  # End marker.
            fragment_offset = fragment_index * RTK_FRAGMENT_LENGTH
            fragment = payload[fragment_offset : fragment_offset + RTK_FRAGMENT_LENGTH]
            logger.debug(f"downloading fragment {fragment_index}")
            await self.host.send_command(
                HCI_RTK_Download_Command(
                    index=download_index, payload=fragment, check_result=True
                )
            )

        logger.debug("download complete!")

        # Read the version again
        response = await self.host.send_command(
            HCI_RTK_Read_ROM_Version_Command(), check_result=True
        )
        if response.return_parameters.status != HCI_SUCCESS:
            logger.warning("can't get ROM version")
        else:
            rom_version = response.return_parameters.version
            logger.debug(f"ROM version after download: {rom_version:04X}")

    async def download_firmware(self):
        if self.driver_info.rom == RTK_ROM_LMP_8723A:
            return await self.download_for_rtl8723a()

        if self.driver_info.rom in (
            RTK_ROM_LMP_8723B,
            RTK_ROM_LMP_8821A,
            RTK_ROM_LMP_8761A,
            RTK_ROM_LMP_8822B,
            RTK_ROM_LMP_8852A,
        ):
            return await self.download_for_rtl8723b()

        raise ValueError("ROM not supported")

    async def init_controller(self):
        await self.download_firmware()
        await self.host.send_command(HCI_Reset_Command(), check_result=True)
        logger.info(f"loaded FW image {self.driver_info.fw_name}")


def rtk_firmware_dir() -> pathlib.Path:
    """
    Returns:
        A path to a subdir of the project data dir for Realtek firmware.
         The directory is created if it doesn't exist.
    """
    from bumble.drivers import project_data_dir

    p = project_data_dir() / "firmware" / "realtek"
    p.mkdir(parents=True, exist_ok=True)
    return p
