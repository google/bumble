# RadioController Qualification Tests

The suite is organized by the actual HCI and LL test-suite chapters. The directory name does not imply Bluetooth SIG qualification or certification.

## Chapter Layout

The suite contains 17 primary test files: nine HCI chapters and eight LL chapters. Each source procedure has one method; its test-case variants are parameters of that method. A printed page label is not a section number.

| Directory | Source Chapter | Test File | Selected Cases |
|---|---|---|---:|
| `hci/` | 4.3 Generic Events | `generic_events_test.py` | 5 |
| `hci/` | 4.4 Device Setup | `device_setup_test.py` | 5 |
| `hci/` | 4.5 Controller Flow Control | `controller_flow_control_test.py` | 1 |
| `hci/` | 4.6 Controller Information | `controller_information_test.py` | 5 |
| `hci/` | 4.7 Device Discovery | `device_discovery_test.py` | 68 |
| `hci/` | 4.8 Host Flow Control | `host_flow_control_test.py` | 1 |
| `hci/` | 4.10 Controller Configuration | `controller_configuration_test.py` | 13 |
| `hci/` | 4.13 LE Connection Management | `connection_management_test.py` | 6 |
| `hci/` | 4.17 Event Versioning | `event_versioning_test.py` | 5 |
| `ll/` | 4.2 Device Discovery | `device_discovery_test.py` | 113 |
| `ll/` | 4.3 Connection | `connection_test.py` | 197 |
| `ll/` | 4.4 Timing | `timing_test.py` | 21 |
| `ll/` | 4.5 Encoding | `encoding_test.py` | 7 |
| `ll/` | 4.6 Frequency Hopping | `frequency_hopping_test.py` | 6 |
| `ll/` | 4.7 Packet Handling | `packet_handling_test.py` | 6 |
| `ll/` | 4.8 Security | `security_test.py` | 38 |
| `ll/` | 4.9 Data Flow | `data_flow_test.py` | 4 |

The chapter counts total 109 HCI and 392 LL cases selected in the workbook. Additional regression cases do not increase coverage of these selected cases.

All selected cases are registered in their source chapters. A case without an executable procedure has an explicit pytest skip reason. `HCI/DDI/BI-03-C` is not applicable: it requires an IUT without LE Set Periodic Advertising Receive Enable support, whereas this DUT supports that command.

Two independent pytest markers describe execution limits:

- `limited` is reserved for sub-microsecond stimulus or measurement precision. These cases execute all available checks at 1-us resolution, using documented integer-us approximations. Timing precision alone never permits a skip.
- `source_conflict` identifies unresolved source procedure, branch or verdict requirements. It permits skipping the unresolved source path and does not imply a Controller capability gap.

A case may carry both markers. `Timing Approximation` in the procedure documents the exact source requirement and chosen integer-us stimulus. The executor rejects skips from timing-only limited procedures; mixed cases can skip for their independent source question. `Source Conflict` documents the unresolved requirement.

Successful labelled executions produce a pytest pass and a protocol `PARTIAL` verdict, preserving the precision or source qualification boundary. Unlabelled procedures that complete their assertions produce a protocol `PASS`. An approximate execution must not be represented as an exact fractional-time measurement.

## Test Infrastructure

The suite owns its wire encoders and HCI probes (`tester.py`), raw connection peer and ACL helpers (`peer.py`), shared lower-tester link operations (`link.py`), periodic advertiser/observer (`periodic.py`), and case registration and verdict logging (`cases.py`). Protocol procedures and chapter-local helpers live in the corresponding `hci/` or `ll/` chapter file. Controller implementation tests live in `../unit/`; they do not test this suite's encoders, registrations or verdict algorithms.

Both HCI and LL chapters use `PROCEDURES |= procedure_cases(...)`. Each variant contains its workbook description and procedure arguments. Use `pytest.param(..., marks=...)` for per-case execution marks. The Test Purpose is a comment immediately above its registration; the implementation docstring retains initial conditions, numbered steps, expected outcomes and specification references. Collection and execution depend only on these test definitions.

The original workbook and review/test-plan documents are not runtime inputs. Case metadata, Source Correction notes and unresolved Source Conflict explanations are maintained alongside the executable procedures.

## Run

```sh
export BSIM_OUT_PATH=/path/to/babble-workspace/bsim
python -m pytest tests/radio_controller/qualification/ -v -rs

# Current qualification tests and implementation unit tests.
python -m pytest tests/radio_controller/ -v -rs

# Optional parallel execution after installing pytest-xdist.
python -m pytest tests/radio_controller/qualification/ -n auto --dist worksteal -q -rs

# Precision-only cases must execute when the native PHY is available.
python -m pytest tests/radio_controller/qualification/ -m 'limited and not source_conflict' -v

# Includes source-only and mixed cases; unresolved source paths may skip.
python -m pytest tests/radio_controller/qualification/ -m source_conflict -v -rs

```

`BSIM_SCAN_MAX_CODED_RANGE_M` declares the simulated `TSPX_scan_max_coded_range` in meters for the Coded latest-scanner case. Its default is 0 for colocated simulated endpoints. The stimulus applies the source's half-us range-delay floor before rounding the combined response delay to whole microseconds, and records the declaration in the protocol log.

Parallel cases have independent PHY processes, simulation IDs, FIFOs and log directories. Identical channels in different simulations cannot interfere. Workers share host resources; some source procedures remain long because they require repeated complete packet observations or simulated silence windows. Parallel scheduling leaves each case's steps, simulation timing and verdict requirements unchanged. See [parallel execution](../README.md#parallel-execution) for installation and worker selection.

## Procedure Requirements

Each registration documents Test Purpose and each case's description. Each method documents Initial Condition, Test Steps, Expected Outcome / Pass verdict, exact source section, printed/PDF pages and case identifiers. All variants belonging to one source procedure use that method with explicit parameters. Unsupported or inapplicable cases state their missing prerequisites. Use `limited` only for sub-microsecond precision and `source_conflict` for unresolved normative requirements. Labelled cases do not receive a full protocol pass verdict.

`not_applicable` is distinct from `unsupported`: the former means the case's applicability conditions are false for this Controller. For example, HCI/DDI/BI-03-C requires a Controller without LE Set Periodic Advertising Receive Enable; this Controller supports that command. LL/FRH/CEN/BV-03-C tests reception of Minimum Number of Used Channels and ten subsequent acknowledged events. Its initial channel map already enables all 37 channels, so map-selection algorithms and update deferral are covered separately by unit tests rather than added as invented qualification steps.

## License

Copyright 2026 Xiaomi Corporation. Licensed under Apache License 2.0; see [LICENSE](../../../LICENSE).
