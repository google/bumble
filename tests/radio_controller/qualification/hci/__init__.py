# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""HCI test procedures organized by normative source chapter."""

from tests.radio_controller.qualification.cases import ProcedureMap

from . import (
    connection_management_test,
    controller_configuration_test,
    controller_flow_control_test,
    controller_information_test,
    device_discovery_test,
    device_setup_test,
    event_versioning_test,
    generic_events_test,
    host_flow_control_test,
)

CHAPTERS = {
    '4.3': generic_events_test,
    '4.4': device_setup_test,
    '4.5': controller_flow_control_test,
    '4.6': controller_information_test,
    '4.7': device_discovery_test,
    '4.8': host_flow_control_test,
    '4.10': controller_configuration_test,
    '4.13': connection_management_test,
    '4.17': event_versioning_test,
}

PROCEDURES: ProcedureMap = {}
for chapter in CHAPTERS.values():
    assert PROCEDURES.keys().isdisjoint(chapter.PROCEDURES)
    PROCEDURES |= chapter.PROCEDURES
