import asyncio
import click
import logging
import json

from bumble.pandora import PandoraDevice, serve
from typing import Dict, Any

BUMBLE_SERVER_GRPC_PORT = 7999
ROOTCANAL_PORT_CUTTLEFISH = 7300


@click.command()
@click.option('--grpc-port', help='gRPC port to serve', default=BUMBLE_SERVER_GRPC_PORT)
@click.option(
    '--rootcanal-port', help='Rootcanal TCP port', default=ROOTCANAL_PORT_CUTTLEFISH
)
@click.option(
    '--transport',
    help='HCI transport',
    default=f'tcp-client:127.0.0.1:<rootcanal-port>',
)
@click.option(
    '--config',
    help='Bumble json configuration file',
)
def main(grpc_port: int, rootcanal_port: int, transport: str, config: str) -> None:
    if '<rootcanal-port>' in transport:
        transport = transport.replace('<rootcanal-port>', str(rootcanal_port))

    bumble_config = retrieve_config(config)
    if 'transport' not in bumble_config.keys():
        bumble_config.update({'transport': transport})
    device = PandoraDevice(bumble_config)

    logging.basicConfig(level=logging.DEBUG)
    asyncio.run(serve(device, port=grpc_port))


def retrieve_config(config: str) -> Dict[str, Any]:
    if not config:
        return {}

    with open(config, 'r') as f:
        return json.load(f)


if __name__ == '__main__':
    main()  # pylint: disable=no-value-for-parameter
