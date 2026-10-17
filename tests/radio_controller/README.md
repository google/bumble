# RadioController Tests

The RadioController suites separate implementation checks from Bluetooth protocol behavior. Complete Host scenarios are executable [samples](../../docs/mkdocs/src/components/radio_controller.md#run-the-samples) in `examples/`. Bumble's existing tests outside this directory retain their original layout.

| Directory | Responsibility | BabbleSim Requirement |
|---|---|---|
| `unit/` | Controller algorithms, state ownership, scheduler and FIFO/thread/clock boundaries, organized by implementation module. | No native PHY is required. |
| `qualification/` | All 501 selected HCI/LL cases, organized by their normative source chapters, with independent lower testers and explicit procedure registrations. | Required for RF cases; pure HCI checks run without it. |

The [qualification chapter map](qualification/README.md) defines the 17 primary test files. Each chapter registers its own case identifiers, descriptions, procedure arguments and pytest marks.

These independently implemented tests do not constitute Bluetooth qualification or imply complete LL.TS/HCI.TS coverage.

Native-PHY fixtures live in `qualification/conftest.py`. Controller unit fixtures and fake-radio helpers live in `unit/conftest.py` and `unit/helpers.py`. Independent packet encoders, raw peers, registration and protocol logging belong to `qualification/`. Protocol verdicts use independent wire observations rather than DUT implementations as their oracle. Unit tests serve the Controller implementation and do not test qualification code.

The [unit module map](unit/README.md) explains the retained boundaries: queue ownership, fragment state, counters, control instants, window admission, resource atomicity and failure cleanup. Independent fixed vectors protect codecs and algorithms; explicit boundary rows replace redundant parameter combinations. Public HCI results and on-air timing belong to the protocol suite. Samples exercise normal Host APIs and do not claim standard-case verdicts.

## Run

From the Bumble checkout:

```sh
# Self-contained implementation checks.
python -m pytest tests/radio_controller/unit/ -v
```

For RF cases, prepare BabbleSim using the [environment setup instructions](../../docs/mkdocs/src/components/radio_controller.md#environment-setup):

```sh
export BSIM_OUT_PATH=/path/to/babble-workspace/bsim
python -m pytest tests/radio_controller/ -v -rs

# Full Bumble regression.
python -m pytest tests/ -v
```

Native cases have independent simulation IDs and support pytest-xdist. They skip when `BSIM_OUT_PATH` is unset; a configured path without the PHY executable fails. Unit collection does not require that environment variable.

## Parallel Execution

```sh
python -m pip install pytest-xdist
export BSIM_OUT_PATH=/path/to/babble-workspace/bsim
python -m pytest tests/radio_controller/ -n auto --dist worksteal -q -rs
```

Each native case owns its PHY process, simulation ID, FIFOs and packet dumps. Worker temporary directories and per-case protocol logs are also separate. Simulations do not interfere through equal RF channels or device addresses. If running multiple pytest invocations with explicit `--basetemp` values, give each invocation its own directory.

`--dist worksteal` redistributes pending cases when workers become idle. This helps balance short unit checks and longer protocol procedures; a single procedure is not split across workers. Use `-n 4` to choose a fixed worker count. All workers share host CPU, memory and storage, so more workers do not guarantee a faster run. See [parallel test execution](../../docs/mkdocs/src/components/radio_controller.md#parallel-test-execution) for the clock model, long-running checks and execution limits.

## License

Copyright 2026 Xiaomi Corporation. The independently written tests are licensed under Apache License 2.0; see the repository [LICENSE](../../LICENSE).
