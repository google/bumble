# RadioController unit tests

Each test file follows its implementation module in `bumble/radio_controller/`.
Keep a unit test when it protects an algorithm boundary, state ownership or a
runtime failure that the selected HCI/LL procedures cannot reliably exercise.
HCI and on-air procedure verdicts belong to `../qualification/`.

| Module tests | Invariants protected |
|---|---|
| `radio`, `radio_parameters`, `radio_advertising` | Independent fixed wire/CRC/CSA vectors, strict input lengths, offset rounding, reproducible address allocation and switching boundaries. |
| `radio_discovery` | Scan gaps and overlapping PHY windows, backoff saturation/streaks and channel-map instants across counter wrap. |
| `radio_scheduler` | Half-open reservation endpoints, chained conflicts, complete nonpreemptive slots and request-relative scheduling grids. |
| `radio_link`, `radio_primary`, `radio_periodic` | One-radio arbitration, live identity collisions, starvation, missed anchors, acquisition/established lifetime transitions and callback-time context replacement. |
| `radio_extended` | Actual header-dependent capacity, PHY-aware chain spacing, identity inheritance and bounded/truncated reassembly. |
| `radio_connection`, `radio_control`, `radio_data_length` | Queue/ARQ ownership, empty Host fragments, exact credit return, delayed indications, retransmission snapshots, colliding negotiations and independent deadlines. |
| `radio_encryption` | Published cipher vectors, TX/RX nonce exhaustion, cached encrypted retries and refresh transitions that must keep user data blocked. |
| `controller_backend`, `controller_records` | Decoder/backend isolation, shared handle publication, live public views and mutable advertising buffers across reconfiguration. |
| `controller_le_advertising`, `controller_le_scanning`, `controller_le_connection`, `controller_le_events` | Atomic failure/resource updates, fragment staging, per-context command routing and state completion when notifications are masked. |
| `radio_babblesim`, `radio_asyncio`, `radio_thread` | Fragmented FIFO I/O, wrong/late ACKs, clock admission, ready-work draining, worker-thread ownership and cleanup after cancellation or startup failure. |

`conftest.py` supplies Controller-only fixtures. `helpers.py` contains a fake RF
endpoint, fixed input builders and shared context setup. These tests do not
import qualification encoders, peers, registrations or verdict algorithms and
need no native PHY.

Avoid constant-by-constant mirrors, encode/decode self-consistency when a fixed
wire vector is available, repeated protocol scenarios and Cartesian products
whose rows all exercise the same condition. Use explicit expected values for
algorithm boundaries. Add no test file solely to cover a forwarding property or
an otherwise fully exercised initialization wrapper.

```sh
python -m pytest tests/radio_controller/unit -q
```
