import asyncio
import click
import logging

from bumble.pandora import PandoraDevice, serve

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
def main(grpc_port: int, rootcanal_port: int, transport: str) -> None:
    if '<rootcanal-port>' in transport:
        transport = transport.replace('<rootcanal-port>', str(rootcanal_port))
    device = PandoraDevice({'transport': transport})
    logging.basicConfig(level=logging.DEBUG)
    asyncio.run(serve(device, port=grpc_port))


if __name__ == '__main__':
    main()  # pylint: disable=no-value-for-parameter
