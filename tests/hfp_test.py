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
from bumble import hfp
from bumble import rfcomm


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
async def run():
    await test_slc()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(run())
