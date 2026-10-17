# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Register and execute independent HCI/LL test procedures."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, TypeAlias

import pytest

ProcedureFunction: TypeAlias = Callable[..., Awaitable[None]]


@dataclass(frozen=True)
class Procedure:
    function: ProcedureFunction | None
    description: str
    parameters: dict[str, Any]
    marks: tuple[Any, ...] = ()


ProcedureMap: TypeAlias = dict[str, Procedure]


def procedure_cases(procedure: ProcedureFunction | None, variants) -> ProcedureMap:
    """Register case descriptions, arguments and optional pytest parameter marks."""
    cases = {}
    for identifier, variant in variants.items():
        description, parameters = getattr(variant, 'values', variant)
        assert isinstance(description, str) and description.strip(), identifier
        assert isinstance(parameters, dict), identifier
        cases[identifier] = Procedure(
            procedure, description, parameters, tuple(getattr(variant, 'marks', ()))
        )
    return cases


def collect_cases(procedures: ProcedureMap, *, radio_cases=(), radio=False):
    """Collect registered cases, retaining fixture and per-case pytest marks."""
    assert procedures, 'empty procedure registration'
    assert set(radio_cases) <= procedures.keys(), 'unregistered radio case'
    cases = []
    for identifier, case in procedures.items():
        if (identifier in radio_cases) != radio:
            continue
        marks = (*getattr(case.function, 'pytestmark', ()), *case.marks)
        names = {mark.name for mark in marks}
        if case.function is None:
            assert 'skip' in names, f'{identifier} has no procedure or skip reason'
        if 'limited' in names and 'source_conflict' not in names:
            assert 'skip' not in names, 'timing precision cannot skip a case'
        cases.append(
            pytest.param(
                identifier,
                case.description,
                case.function,
                case.parameters,
                marks,
                id=identifier,
                marks=marks,
            )
        )
    return cases


async def verify_case(tester, identifier, description, procedure, parameters, marks):
    labels = sorted({mark.name for mark in marks} & {'limited', 'source_conflict'})
    tester.output.write(
        f'CASE {identifier}\nDESCRIPTION {description}\n'
        f'PROCEDURE {procedure.__doc__.strip()}\n'
        f'VARIANT {parameters}\n'
        f'LABELS {",".join(labels) or "none"}\n'
    )
    if 'limited' in labels:
        tester.output.write('TIMING APPROXIMATION resolution_us=1\n')
    tester.output.flush()
    try:
        await procedure(tester, **parameters)
    except pytest.skip.Exception as error:
        if 'limited' in labels and 'source_conflict' not in labels:
            raise AssertionError(
                'A timing-only limited case must execute its 1-us approximation; '
                'skipping requires a source_conflict label'
            ) from error
        raise
    tester.output.write(f'{"PARTIAL" if labels else "PASS"} {identifier}\n')
    tester.output.flush()
