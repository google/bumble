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
import logging

from .hci import HCI_Packet
from .helpers import PacketTracer

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
class HCI_Bridge:
    class Forwarder:
        def __init__(self, hci_sink, sender_hci_sink, packet_filter, trace):
            self.hci_sink = hci_sink
            self.sender_hci_sink = sender_hci_sink
            self.packet_filter = packet_filter
            self.trace = trace

        def on_packet(self, packet):
            # Convert the packet bytes to an object
            hci_packet = HCI_Packet.from_bytes(packet)

            # Filter the packet
            if self.packet_filter is not None:
                filtered = self.packet_filter(hci_packet)
                if filtered is not None:
                    packet, respond_to_sender = filtered
                    hci_packet = HCI_Packet.from_bytes(packet)
                    if respond_to_sender:
                        self.sender_hci_sink.on_packet(packet)
                        return

            # Analyze the packet
            self.trace(hci_packet)

            # Bridge the packet
            self.hci_sink.on_packet(packet)

    def __init__(
        self,
        hci_host_source,
        hci_host_sink,
        hci_controller_source,
        hci_controller_sink,
        host_to_controller_filter=None,
        controller_to_host_filter=None,
    ):
        tracer = PacketTracer(emit_message=logger.info)
        host_to_controller_forwarder = HCI_Bridge.Forwarder(
            hci_controller_sink,
            hci_host_sink,
            host_to_controller_filter,
            lambda packet: tracer.trace(packet, 0),
        )
        hci_host_source.set_packet_sink(host_to_controller_forwarder)

        controller_to_host_forwarder = HCI_Bridge.Forwarder(
            hci_host_sink,
            hci_controller_sink,
            controller_to_host_filter,
            lambda packet: tracer.trace(packet, 1),
        )
        hci_controller_source.set_packet_sink(controller_to_host_forwarder)
