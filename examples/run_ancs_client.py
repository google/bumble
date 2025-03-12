# Copyright 2025 Google LLC
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
import sys
import os
import logging
from bumble.colors import color

from bumble.device import Device, Peer
from bumble.transport import open_transport
from bumble.profiles.ancs import (
    AncsClient,
    AppAttribute,
    AppAttributeId,
    EventFlags,
    EventId,
    Notification,
    NotificationAttributeId,
)


# -----------------------------------------------------------------------------
_cached_app_names: dict[str, str] = {}
_notification_queue = asyncio.Queue[Notification]()


async def process_notifications(ancs_client: AncsClient):
    while True:
        notification = await _notification_queue.get()

        prefix = " "
        if notification.event_id == EventId.NOTIFICATION_ADDED:
            print_color = "green"
            if notification.event_flags & EventFlags.PRE_EXISTING:
                prefix = " Existing "
            else:
                prefix = " New "
        elif notification.event_id == EventId.NOTIFICATION_REMOVED:
            print_color = "red"
        elif notification.event_id == EventId.NOTIFICATION_MODIFIED:
            print_color = "yellow"
        else:
            print_color = "white"

        print(
            color(
                (
                    f"[{notification.event_id.name}]{prefix}Notification "
                    f"({notification.notification_uid}):"
                ),
                print_color,
            )
        )
        print(color("  Event ID:      ", "yellow"), notification.event_id.name)
        print(color("  Event Flags:   ", "yellow"), notification.event_flags.name)
        print(color("  Category ID:   ", "yellow"), notification.category_id.name)
        print(color("  Category Count:", "yellow"), notification.category_count)

        if notification.event_id not in (
            EventId.NOTIFICATION_ADDED,
            EventId.NOTIFICATION_MODIFIED,
        ):
            continue

        requested_attributes = [
            NotificationAttributeId.APP_IDENTIFIER,
            NotificationAttributeId.TITLE,
            NotificationAttributeId.SUBTITLE,
            NotificationAttributeId.MESSAGE,
            NotificationAttributeId.DATE,
        ]
        if notification.event_flags & EventFlags.NEGATIVE_ACTION:
            requested_attributes.append(NotificationAttributeId.NEGATIVE_ACTION_LABEL)
        if notification.event_flags & EventFlags.POSITIVE_ACTION:
            requested_attributes.append(NotificationAttributeId.POSITIVE_ACTION_LABEL)

        attributes = await ancs_client.get_notification_attributes(
            notification.notification_uid, requested_attributes
        )
        max_attribute_name_width = max(
            (len(attribute.attribute_id.name) for attribute in attributes)
        )
        app_identifier = str(
            next(
                (
                    attribute.value
                    for attribute in attributes
                    if attribute.attribute_id == NotificationAttributeId.APP_IDENTIFIER
                )
            )
        )
        if app_identifier not in _cached_app_names:
            app_attributes = await ancs_client.get_app_attributes(
                app_identifier, [AppAttributeId.DISPLAY_NAME]
            )
            _cached_app_names[app_identifier] = app_attributes[0].value
        app_name = _cached_app_names[app_identifier]

        for attribute in attributes:
            padding = ' ' * (
                max_attribute_name_width - len(attribute.attribute_id.name)
            )
            suffix = (
                f" ({app_name})"
                if attribute.attribute_id == NotificationAttributeId.APP_IDENTIFIER
                else ""
            )
            print(
                color(f"  {attribute.attribute_id.name}:{padding}", "blue"),
                f"{attribute.value}{suffix}",
            )

        print()


def on_ancs_notification(notification: Notification) -> None:
    _notification_queue.put_nowait(notification)


async def handle_command_client(
    ancs_client: AncsClient, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    while True:
        command = (await reader.readline()).decode("utf-8").strip()

        try:
            command_name, command_args = command.split(" ", 1)
            if command_name == "+":
                notification_uid = int(command_args)
                await ancs_client.perform_positive_action(notification_uid)
            elif command_name == "-":
                notification_uid = int(command_args)
                await ancs_client.perform_negative_action(notification_uid)
            else:
                writer.write(f"unknown command {command_name}".encode("utf-8"))
        except Exception as error:
            writer.write(f"ERROR: {error}\n".encode("utf-8"))


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 3:
        print(
            'Usage: run_ancs_client.py <device-config> <transport-spec> '
            '<bluetooth-address> <mtu>'
        )
        print('example: run_ancs_client.py device1.json usb:0 E1:CA:72:48:C4:E8 512')
        return
    device_config, transport_spec, bluetooth_address, mtu = sys.argv[1:]

    print('<<< connecting to HCI...')
    async with await open_transport(transport_spec) as hci_transport:
        print('<<< connected')

        # Create a device to manage the host, with a custom listener
        device = Device.from_config_file_with_hci(
            device_config, hci_transport.source, hci_transport.sink
        )
        await device.power_on()

        # Connect to the peer
        print(f'=== Connecting to {bluetooth_address}...')
        connection = await device.connect(bluetooth_address)
        print(f'=== Connected: {connection}')

        await connection.encrypt()

        peer = Peer(connection)
        mtu_int = int(mtu)
        if mtu_int:
            new_mtu = await peer.request_mtu(mtu_int)
            print(f'ATT MTU = {new_mtu}')
        ancs_client = await AncsClient.for_peer(peer)
        if ancs_client is None:
            print("!!! no ANCS service found")
            return
        await ancs_client.start()

        print('Subscribing to updates')
        ancs_client.on("notification", on_ancs_notification)

        # Process all notifications in a task.
        notification_processing_task = asyncio.create_task(
            process_notifications(ancs_client)
        )

        # Accept a TCP connection to handle commands.
        tcp_server = await asyncio.start_server(
            lambda reader, writer: handle_command_client(ancs_client, reader, writer),
            '127.0.0.1',
            9000,
        )
        print("Accepting command client on port 9000")
        async with tcp_server:
            await tcp_server.serve_forever()


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
asyncio.run(main())
