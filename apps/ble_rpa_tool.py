# Copyright 2023 Google LLC
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

import click
from bumble.colors import color
from bumble.hci import Address
from bumble.helpers import generate_irk, verify_rpa_with_irk


@click.group()
def cli():
    '''
    This is a tool for generating IRK, RPA,
    and verifying IRK/RPA pairs
    '''


@click.command()
def gen_irk() -> None:
    print(generate_irk().hex())


@click.command()
@click.argument("irk", type=str)
def gen_rpa(irk: str) -> None:
    irk_bytes = bytes.fromhex(irk)
    rpa = Address.generate_private_address(irk_bytes)
    print(rpa.to_string(with_type_qualifier=False))


@click.command()
@click.argument("irk", type=str)
@click.argument("rpa", type=str)
def verify_rpa(irk: str, rpa: str) -> None:
    address = Address(rpa)
    irk_bytes = bytes.fromhex(irk)
    if verify_rpa_with_irk(address, irk_bytes):
        print(color("Verified", "green"))
    else:
        print(color("Not Verified", "red"))


def main():
    cli.add_command(gen_irk)
    cli.add_command(gen_rpa)
    cli.add_command(verify_rpa)
    cli()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    main()
