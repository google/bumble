# Copyright 2021-2022 Google LLC
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
import asyncio
import logging
import os
import pytest

from typing import Tuple

from .test_utils import TwoDevices
from bumble import core
from bumble import hfp
from bumble import rfcomm
from bumble import hci


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
async def make_hfp_connections(
    hf_config: hfp.Configuration,
) -> Tuple[hfp.HfProtocol, hfp.HfpProtocol]:
    # Setup devices
    devices = TwoDevices()
    await devices.setup_connection()

    # Setup RFCOMM channel
    wait_dlc = asyncio.get_running_loop().create_future()
    rfcomm_channel = rfcomm.Server(devices.devices[0]).listen(wait_dlc.set_result)
    assert devices.connections[0]
    assert devices.connections[1]
    client_mux = await rfcomm.Client(devices.connections[1]).start()

    client_dlc = await client_mux.open_dlc(rfcomm_channel)
    server_dlc = await wait_dlc

    # Setup HFP connection
    hf = hfp.HfProtocol(client_dlc, hf_config)
    ag = hfp.HfpProtocol(server_dlc)
    return hf, ag


# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_slc():
    hf_config = hfp.Configuration(
        supported_hf_features=[], supported_hf_indicators=[], supported_audio_codecs=[]
    )
    hf, ag = await make_hfp_connections(hf_config)

    async def ag_loop():
        while line := await ag.next_line():
            if line.startswith('AT+BRSF'):
                ag.send_response_line('+BRSF: 0')
            elif line.startswith('AT+CIND=?'):
                ag.send_response_line(
                    '+CIND: ("call",(0,1)),("callsetup",(0-3)),("service",(0-1)),'
                    '("signal",(0-5)),("roam",(0,1)),("battchg",(0-5)),'
                    '("callheld",(0-2))'
                )
            elif line.startswith('AT+CIND?'):
                ag.send_response_line('+CIND: 0,0,1,4,1,5,0')
            ag.send_response_line('OK')

    ag_task = asyncio.create_task(ag_loop())

    await hf.initiate_slc()
    ag_task.cancel()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_sco_setup():
    devices = TwoDevices()

    # Enable Classic connections
    devices[0].classic_enabled = True
    devices[1].classic_enabled = True

    # Start
    await devices[0].power_on()
    await devices[1].power_on()

    connections = await asyncio.gather(
        devices[0].connect(
            devices[1].public_address, transport=core.BT_BR_EDR_TRANSPORT
        ),
        devices[1].accept(devices[0].public_address),
    )

    def on_sco_request(_connection, _link_type: int):
        connections[1].abort_on(
            'disconnection',
            devices[1].send_command(
                hci.HCI_Enhanced_Accept_Synchronous_Connection_Request_Command(
                    bd_addr=connections[1].peer_address,
                    **hfp.ESCO_PARAMETERS[
                        hfp.DefaultCodecParameters.ESCO_CVSD_S1
                    ].asdict(),
                )
            ),
        )

    devices[1].on('sco_request', on_sco_request)

    sco_connection_futures = [
        asyncio.get_running_loop().create_future(),
        asyncio.get_running_loop().create_future(),
    ]

    for device, future in zip(devices, sco_connection_futures):
        device.on('sco_connection', future.set_result)

    await devices[0].send_command(
        hci.HCI_Enhanced_Setup_Synchronous_Connection_Command(
            connection_handle=connections[0].handle,
            **hfp.ESCO_PARAMETERS[hfp.DefaultCodecParameters.ESCO_CVSD_S1].asdict(),
        )
    )
    sco_connections = await asyncio.gather(*sco_connection_futures)

    sco_disconnection_futures = [
        asyncio.get_running_loop().create_future(),
        asyncio.get_running_loop().create_future(),
    ]
    for future, sco_connection in zip(sco_disconnection_futures, sco_connections):
        sco_connection.on('disconnection', future.set_result)

    await sco_connections[0].disconnect()
    await asyncio.gather(*sco_disconnection_futures)


# -----------------------------------------------------------------------------
async def run():
    await test_slc()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(run())
