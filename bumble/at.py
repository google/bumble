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

from typing import List, Union


def tokenize_parameters(buffer: bytes) -> List[bytes]:
    """Split input parameters into tokens.
    Removes space characters outside of double quote blocks:
    T-rec-V-25 - 5.2.1 Command line general format: "Space characters (IA5 2/0)
    are ignored [..], unless they are embedded in numeric or string constants"
    Raises ValueError in case of invalid input string."""

    tokens = []
    in_quotes = False
    token = bytearray()
    for b in buffer:
        char = bytearray([b])

        if in_quotes:
            token.extend(char)
            if char == b'\"':
                in_quotes = False
                tokens.append(token[1:-1])
                token = bytearray()
        else:
            if char == b' ':
                pass
            elif char == b',' or char == b')':
                tokens.append(token)
                tokens.append(char)
                token = bytearray()
            elif char == b'(':
                if len(token) > 0:
                    raise ValueError("open_paren following regular character")
                tokens.append(char)
            elif char == b'"':
                if len(token) > 0:
                    raise ValueError("quote following regular character")
                in_quotes = True
                token.extend(char)
            else:
                token.extend(char)

    tokens.append(token)
    return [bytes(token) for token in tokens if len(token) > 0]


def parse_parameters(buffer: bytes) -> List[Union[bytes, list]]:
    """Parse the parameters using the comma and parenthesis separators.
    Raises ValueError in case of invalid input string."""

    tokens = tokenize_parameters(buffer)
    accumulator: List[list] = [[]]
    current: Union[bytes, list] = bytes()

    for token in tokens:
        if token == b',':
            accumulator[-1].append(current)
            current = bytes()
        elif token == b'(':
            accumulator.append([])
        elif token == b')':
            if len(accumulator) < 2:
                raise ValueError("close_paren without matching open_paren")
            accumulator[-1].append(current)
            current = accumulator.pop()
        else:
            current = token

    accumulator[-1].append(current)
    if len(accumulator) > 1:
        raise ValueError("missing close_paren")
    return accumulator[0]
