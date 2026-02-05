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


from bumble import core


class AtParsingError(core.InvalidPacketError):
    """Error raised when parsing AT commands fails."""


def tokenize_parameters(buffer: bytes) -> list[bytes]:
    """Split input parameters into tokens.
    Removes space characters outside of double quote blocks:
    T-rec-V-25 - 5.2.1 Command line general format: "Space characters (IA5 2/0)
    are ignored [..], unless they are embedded in numeric or string constants"
    Raises AtParsingError in case of invalid input string."""

    tokens: list[bytearray] = []
    in_quotes = False
    token = bytearray()
    for b in buffer:
        char = bytearray([b])

        if in_quotes:
            token.extend(char)
            if char == b'"':
                in_quotes = False
                tokens.append(token[1:-1])
                token = bytearray()
        else:
            match char:
                case b' ':
                    pass
                case b',' | b')':
                    tokens.append(token)
                    tokens.append(char)
                    token = bytearray()
                case b'(':
                    if len(token) > 0:
                        raise AtParsingError("open_paren following regular character")
                    tokens.append(char)
                case b'"':
                    if len(token) > 0:
                        raise AtParsingError("quote following regular character")
                    in_quotes = True
                    token.extend(char)
                case _:
                    token.extend(char)

    tokens.append(token)
    return [bytes(token) for token in tokens if len(token) > 0]


def parse_parameters(buffer: bytes) -> list[bytes | list]:
    """Parse the parameters using the comma and parenthesis separators.
    Raises AtParsingError in case of invalid input string."""

    tokens = tokenize_parameters(buffer)
    accumulator: list[list] = [[]]
    current: bytes | list = b''

    for token in tokens:
        match token:
            case b',':
                accumulator[-1].append(current)
                current = b''
            case b'(':
                accumulator.append([])
            case b')':
                if len(accumulator) < 2:
                    raise AtParsingError("close_paren without matching open_paren")
                accumulator[-1].append(current)
                current = accumulator.pop()
            case _:
                current = token

    accumulator[-1].append(current)
    if len(accumulator) > 1:
        raise AtParsingError("missing close_paren")
    return accumulator[0]
