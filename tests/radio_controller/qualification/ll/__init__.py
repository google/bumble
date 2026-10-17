# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""LL test procedures organized by normative source chapter."""

from tests.radio_controller.qualification.cases import ProcedureMap

from . import (
    connection_test,
    data_flow_test,
    device_discovery_test,
    encoding_test,
    frequency_hopping_test,
    packet_handling_test,
    security_test,
    timing_test,
)

CHAPTERS = {
    '4.2': device_discovery_test,
    '4.3': connection_test,
    '4.4': timing_test,
    '4.5': encoding_test,
    '4.6': frequency_hopping_test,
    '4.7': packet_handling_test,
    '4.8': security_test,
    '4.9': data_flow_test,
}

PROCEDURES: ProcedureMap = {}
for chapter in CHAPTERS.values():
    assert PROCEDURES.keys().isdisjoint(chapter.PROCEDURES)
    PROCEDURES |= chapter.PROCEDURES
