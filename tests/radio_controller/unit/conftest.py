# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Controller-only fixtures; no qualification peers or verdict algorithms."""

import asyncio
from types import SimpleNamespace

import pytest

from bumble import hci
from bumble.controller import Controller
from bumble.radio_controller.controller_backend import RadioBackend
from bumble.radio_controller.radio_connection import Connection
from tests.radio_controller.unit.helpers import PARAMETERS, FakeRadio


@pytest.fixture
def controller():
    async def create():
        return Controller(
            'test',
            backend=RadioBackend(FakeRadio()),
            public_address='F0:F1:F2:F3:F4:01',
        )

    result = asyncio.run(create())
    result.events = []
    result.send_hci_packet = result.events.append
    result.event_mask = result.le_event_mask = (1 << 64) - 1
    return result


@pytest.fixture
def connection(controller):
    result = Connection(
        controller.backend.link,
        PARAMETERS,
        hci.Address('F0:F1:F2:F3:F4:02'),
        hci.Role.PERIPHERAL,
        0,
    )
    controller.backend.link.connections[result.handle] = result
    return result


@pytest.fixture
def hci_dut(controller):
    """Exercise command dispatch while leaving time and RF under test control."""

    async def command(packet, status=hci.HCI_ErrorCode.SUCCESS):
        offset = len(controller.events)
        controller.on_packet(bytes(packet))
        await asyncio.sleep(0)
        reply = next(
            event
            for event in controller.events[offset:]
            if isinstance(
                event, (hci.HCI_Command_Complete_Event, hci.HCI_Command_Status_Event)
            )
        )
        result = getattr(reply, 'return_parameters', reply)
        assert result.status == status
        return result

    async def event(event_type):
        await asyncio.sleep(0)
        for index, packet in enumerate(controller.events):
            if isinstance(packet, event_type):
                return controller.events.pop(index)
        pytest.fail(f'Missing {event_type.__name__}')

    async def masks():
        controller.event_mask = controller.le_event_mask = (1 << 64) - 1

    return SimpleNamespace(input=controller, command=command, event=event, masks=masks)
