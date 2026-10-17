# Radio-backed LE Controller

`Controller` retains Bumble's existing in-memory simulation and `link=local_link` API. Selecting `backend=RadioBackend(radio)` executes Bluetooth LE wire procedures through a physical-channel simulator, while reusing the same HCI entry point, basic command handlers, address storage, connection-handle allocator and Host-visible connection and advertising-set records.

The radio implementation is experimental. It can run a Bumble Host and Controller together in a Python process, or expose a Unix-socket HCI endpoint to an external Host. Each Controller joins a [BabbleSim](https://babblesim.github.io/) PHY as an independent device. The Python examples below run without a test framework or RTOS image.

## Layers

```text
Host
  | HCI packets
Controller                     HCI dispatch, shared state and command responses
LeControllerProcedures         HCI command validation and configuration
LeControllerEvents             Link Layer notifications and masked HCI events
  | procedure configuration and callbacks
RadioLink                      single-radio deadlines and procedure dispatch
ExtendedProcedures             auxiliary advertising, scanning and connections
Connection / ControlProcedures ACL ARQ, negotiated updates and instants
Encryption                     CCM, key refresh and authenticated payload timeout
  | transmit / receive / wait
Radio                          integer-microsecond backend contract
  |
BabbleSimRadio                 Python FIFO client, uncoded and Coded RF requests
  |
BabbleSim PHY / BLE_simple      RF attenuation, collisions and receive results
```

`RadioBackend` configures the Controller's capabilities and binds its LE procedures to a radio. `LeControllerProcedures` is the HCI command endpoint; advertising, scanning/synchronization and connected procedures each have a command group. These groups inherit one `LeControllerContext`, so they use one configuration and notification state without forwarding handlers or a second dispatch table. `LeControllerEvents` translates Link Layer notifications into masked HCI events. `RadioLink` selects the next operation on the single radio; `ExtendedProcedures` handles auxiliary transactions, while `Connection` owns ACL retransmission and the control-PDU queue. Encryption, Data Length and other control procedures enqueue through the connection rather than manipulating its queue directly. `ControlProcedures` owns Link Layer negotiation and instant-based updates. None of these procedure objects starts an independent radio task. LocalLink retains its original permissive/synthetic handlers.

Radio procedures use integer simulation timestamps and asynchronous `transmit`, `receive` and `advance_to_us` operations. Each radio submits its PHY requests directly and waits for its own responses. `RadioControllerWorker` owns a Controller thread and its HCI handoff. `BabbleSimSession` starts and stops these workers and can supply a shared Host clock to `RadioEventLoop`. Selecting a radio backend does not automatically enable LocalLink-only features: its command whitelist prevents unsupported operations from falling back to synthetic success.

The radio implementation modules are grouped in `bumble/radio_controller/`; `bumble.controller.Controller` remains the HCI-facing entry point.

`radio_discovery.py` defines the connectionless advertising, scanning, initiating and periodic-sync records, together with scan backoff and scan-window selection. The HCI adapter configures these records; `RadioLink` owns their active lifetimes and performs RF operations. `radio_parameters.py` holds the immutable CONNECT_IND parameters and shared connection-timing/channel-map validation, independently of a live connection or radio.

Legacy and auxiliary advertising share request-address validation and SCAN_REQ encoding in `radio_advertising.py`. `radio_primary.py` implements primary-channel packet exchanges and complete advertising-event duration calculations. `radio_periodic.py` implements periodic transmission and synchronization reception. These stateless operations execute with an explicit owning `RadioLink`; its scheduled RF entry points bind directly to those functions. Reservation selection, operation priorities, active lifetimes and event rescheduling remain in `RadioLink`. `ExtendedProcedures` continues to own auxiliary exchanges and chains. Each operation runs on the same radio.

`RadioLink` publishes every new ACL connection through one transition and owns Access Address allocation and periodic RF activation. Public Controller advertising records derive their data, enabled state and random address from the live radio contexts. Advertising, scan-response and periodic-advertising buffers remain mutable `bytearray` objects shared with RF execution; packet encoding captures immutable bytes. This includes the public `AdvertisingSet.periodic_advertising_data` field used by LocalLink. Legacy configuration retains its own data before its first radio context is created. LocalLink records continue to store their own data and timer state. `RadioConnectionRecord` exposes a live radio connection's identity through the existing Controller connection interface; the peer-address and handle dictionaries are lookup indexes with explicit publication/removal transitions. Event masks affect notification delivery, independently of these state transitions.

HCI handlers retain command validation, status selection and fragment assembly. Feature Exchange responses, parameter-request rejection and their pending state belong to `ControlProcedures`.

## Implemented Scope

| Procedure | Current radio path |
|---|---|
| PHY | LE 1M, LE 2M and LE Coded; S=8 advertising and selectable S=2/S=8 connection transmission. Primary advertising uses LE 1M or LE Coded; secondary and data channels also support LE 2M. |
| Legacy advertising | Undirected connectable/scannable, scannable-only, nonconnectable and high/low duty directed advertising on channels 37/38/39; public or configured random addresses, TargetA validation and the 1.28-s high-duty timeout. |
| Scanning | Passive/active legacy and extended scanning, LE 1M/Coded scan windows, auxiliary following on all three PHYs, scan backoff, duplicate filtering, duration/period and Scan Timeout events. Reports require received PDUs. |
| Extended advertising | Up to eight independently configured sets on one radio; connectable, scannable or nonconnectable, with directed and anonymous modes where permitted. Primary ADV_EXT_IND packets reference a shared auxiliary event. AUX_SCAN_REQ/RSP, AUX_CONNECT_REQ/RSP, AUX_CHAIN_IND, ADI/SID, HCI data fragmentation, report reassembly/status, per-set duration/event limits and scan-request notifications are supported. Extended HCI can also select legacy PDUs. |
| Filtering | Public/random entries in the Filter Accept List, with advertising, scanning and initiating filter policies. Resolving lists and address resolution are not supported. |
| Periodic advertising | SyncInfo, AUX_SYNC_IND/AUX_CHAIN_IND, CRCInit/access-address selection and CSA #2 hopping on LE 1M, LE 2M or LE Coded. |
| Periodic synchronization | Eight synchronization slots, with at most one pending creation request, selected directly or through the Periodic Advertiser List by address, address type and SID. Each established context owns its handle, event counter, receive window, reports, skip and timeout. Duplicate creation returns Connection Already Exists. Cancellation affects only the pending request; termination and sync loss affect only their selected context. |
| Connections | Up to eight ACL connections across Central and Peripheral roles, with one pending initiating procedure. Each connection owns its handle, Access Address, CRCInit, ARQ state, encryption, data-length negotiation and control instants. Legacy and auxiliary initiation support CSA #1/#2, PHY-specific first-window timing and widened receive windows. Duplicate peers cannot replace existing connections. |
| LE encryption | Actual LL_ENC/START_ENC and PAUSE_ENC exchanges, Host LTK requests/replies, AES-CCM ciphertext and MIC, per-direction counters and retransmission, Encryption Change and Key Refresh Complete events. Corrupt authentication terminates the ACL with MIC Failure; missing procedure responses use the 40-s LL response timeout. LE Ping and configurable authenticated payload supervision use simulation time and HCI event masks. |
| ACL and DLE | 251-byte HCI buffers; LL_LENGTH_REQ/RSP negotiation, directional octet/time limits and Data Length Change events. Host data is fragmented to the negotiated LL limits, preserving LLID, SN/NESN, retransmission and duplicate suppression. A completed-packet credit is returned only after the final fragment is acknowledged. ATT/GATT remains in the Host. |
| Link control | Host/peer-initiated remote feature and version discovery, cached queries and unknown responses. Version Exchange sends one local indication per connection and retains the first peer tuple; its result and timeout use real HCI completion events. Termination, supervision and LL response procedures retain independent deadlines. Receive search windows stop at the earliest protocol deadline. Both roles support connection parameter requests/replies/rejections; Central falls back to direct UPDATE_IND for an unsupported peer. Channel-map and PHY changes take effect at the negotiated event-counter instant, including counter wraparound. HCI Read RSSI reports valid received-packet measurements, not a fixed signal strength. |

Legacy data is limited to 31 bytes. Nonlegacy advertising, scan-response and periodic data support up to 1650 bytes through auxiliary chains. Each advertising PDU has at most 255 payload octets; its actual extended header determines the available data capacity. Connectable advertising cannot be chained: its single auxiliary PDU holds at most 245 data bytes with AdvA and ADI, reduced by TargetA and optional TxPower fields. Advertising and periodic intervals must leave room for the complete chains. Transmit power can be selected from -127 to +20 dBm; HCI's no-preference value selects 0 dBm. The advertised HCI capacity and feature mask describe this radio path, not LocalLink's synthetic capabilities.

The Minimum Number of Used Channels procedure is supported in both roles. Controller-side Peripheral policy can call `connection.controls.request_minimum_channels(phys, minimum)` on its radio thread after Feature Exchange has confirmed peer support. The indication uses the existing control-PDU queue and Link Layer acknowledgement; it does not introduce a Host command or a response timer. `minimum` is 2–37, and `phys` selects LE 1M, LE 2M and/or LE Coded.

The Central retains the latest indication per connection and applies it when the Peripheral-to-Central PHY matches that indication. Its deterministic channel-map policy prefers Host-classified usable channels, then adds other channel indices in ascending order until the requested minimum is met. This is an implementation policy, not a Core-defined AFH algorithm or a mandatory immediate-update deadline. Changes reuse the existing `LL_CHANNEL_MAP_IND`/Instant procedure. An in-flight update is not overwritten; the requirement is re-evaluated after it completes, after a PHY change, and on subsequent Host classification changes.

DLE connections begin with the peer's default 27-octet limits. The Controller supports up to 251 octets and 17040 us, but actual packet sizes depend on both peers' negotiated limits, the selected PHY and the connection interval. Prospective PHY limits constrain new fragments from the role-specific control transmission or reception, not merely from HCI command admission, and apply before Instant. Pending interval updates also constrain new fragments; an already transmitted PDU retains its payload until acknowledged. HCI suggested defaults apply to new connections, and effective length/time changes are reported to the Host.

Constants follow their owning layer: `bumble.ll` defines PDU fields, sizes and Link Layer timing; `bumble.hci` defines HCI command units, parameter bounds, report fields and complete advertising-data limits; `bumble.radio_controller.radio` defines PHY airtime coefficients and radio implementation defaults. Names use `PDU_`, `LL_`, `HCI_`, `PHY_` or `RADIO_` prefixes, with `MIN`/`MAX` for bounds, `SIZE` for octet counts, `MASK` for encoded bit masks, and `_US`/`_BITS`/`_MHZ` for other units. Definitions are grouped by protocol function and annotated with their Core references and what each length includes. Comments precede the definitions. BabbleSim wire encodings and transport watchdogs remain in `radio_babblesim.py`; receive-window slack and other implementation policies are kept separate from specification limits.

Advertising/scanning command intervals use 625 us, connection/periodic intervals use 1250 us, supervision timeouts use 10000 us, and AuxPtr offsets use 30-us or 300-us units. `LL_IFS_US` and `LL_MAFS_US` define frame spacing. `RADIO_AUX_OFFSET_DEFAULT_US` remains in `radio_extended.py` as an implementation scheduling choice, not a specification minimum; its final offset is rounded up after accounting for the PDU's actual airtime.

This is **not a complete Controller or a Bluetooth qualification claim**. Privacy, ISO, PAwR and Bluetooth Classic are not implemented. Unsupported commands or parameter combinations return errors, rather than invoking the original Controller's synthetic implementations.

Advertising, scanning, initiation, mixed-role ACL connections, periodic advertising and synchronization share one radio. The scheduler selects due operations in simulation-time order; equal deadlines prioritize ACL, periodic TX, periodic RX, then flexible advertising. Before starting periodic TX or RX, it also checks whether the planned window overlaps a higher-priority reservation, even when the starts differ. A conflicting periodic event is skipped rather than transmitted late; flexible advertising searches for a free slot. Equal-anchor ACLs use their last serviced event to break ties. Scanning and initiation alternate their available windows. An admitted TX/RX is nonpreemptive; an event missed through a radio conflict advances its counter and applies pending instants without transmitting at an incorrect timestamp. Each connection and synchronization retains its own timeout.

The periodic TX estimate covers its complete configured chain and scheduling margin. Periodic RX admission checks the receive-address window, including window widening; an actual received packet may finish beyond that estimate. Window arbitration is a scheduling policy, not a guarantee that unknown packet airtime cannot overlap another event. Priorities remain fixed; the scheduler does not raise them based on skipped events.

Initial connection windows and periodic phases prefer available radio slots. This is not a guarantee that arbitrary interval, PHY and payload combinations fit one radio. Legal coexistence does not guarantee lossless traffic: overlapping windows may miss events and sustained overload may cause a supervision or synchronization timeout. The Controller does not automatically retune Host parameters or guarantee application throughput. Per-procedure size and timing validation still applies; another active procedure alone does not prohibit enabling a legal state.

Encryption uses the existing `cryptography` AES-CCM implementation, checked against published Core sample vectors and an independently encoded raw-PDU peer. IV/SKD generation and HCI LE Rand use the radio's seeded simulation generator so fixed test inputs remain reproducible; this Controller is not a source of production cryptographic randomness. Native regression coverage is separate from the complete source-to-code audit described in the test suite's README.

Wire formats and timing refer to [Bluetooth Core 6.3](https://www.bluetooth.com/specifications/specs/core-specification-6-3/), including the Link Layer and Physical Layer requirements in Vol 6 and HCI in Vol 4, Part E. Tests use independently encoded peer packets and reference vectors to check frame spacing, AuxPtr, SyncInfo, channel selection and update instants. The HCI/LL chapter modules record their source revisions, case descriptions and procedure references directly in their test definitions. Interoperability testing against independently implemented Controllers complements, but does not replace, those normative checks.

## Environment Setup

Use Linux and Python 3.11 or newer; the Controller workers and examples use `asyncio.Runner`. Python communicates directly with the PHY through FIFOs and does not load BabbleSim shared libraries. Python and the PHY must use the same native byte order, as required by BabbleSim's wire protocol, but need not use the same pointer width.

Create a Bumble checkout and Python environment:

```sh
git clone https://github.com/google/bumble.git
cd bumble
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m pip install west pytest pytest-asyncio
export BUMBLE_ROOT="$PWD"
```

Use a checkout containing the radio implementation. The commands assume the source files described on this page are present; an upstream release without them cannot run these examples.

On Ubuntu, install the native build tools. The multilib packages are needed because BabbleSim also builds 32-bit artifacts:

```sh
sudo apt install git make gcc-multilib g++-multilib
```

Fetch a standalone BabbleSim workspace using its [official west manifest](https://github.com/BabbleSim/bsim_west). Here, west downloads the BabbleSim components:

```sh
west init -m https://github.com/BabbleSim/bsim_west.git /path/to/babble-workspace
cd /path/to/babble-workspace/bsim
west update
export BSIM_OUT_PATH="$PWD"
export BSIM_COMPONENTS_PATH="$PWD/components"
make everything -j8
cd "$BUMBLE_ROOT"
```

The [BabbleSim build](https://babblesim.github.io/building.html) produces the PHY and its modem/channel plugins in `$BSIM_OUT_PATH/bin` and `$BSIM_OUT_PATH/lib`. Keep that build output intact for the native PHY; the Python endpoints themselves require no native libraries. If using an existing BabbleSim installation, set `BSIM_OUT_PATH` to that build output instead. The FIFO layouts were tested with `bsim_west` manifest revision `0673623452f0a3cb50b7563c32ac7683304cb6fc`. LE 1M/2M use the original 2G4 request format. LE Coded uses the PHY's v2 requests and continuation protocol, with separate S=8 FEC1 and S=2/S=8 FEC2 stages. A different native protocol revision needs layout verification before use.

Radio packet timestamps use half-open intervals: `start_us` is the first occupied microsecond and `end_us` is the boundary immediately after the packet. BabbleSim's packet-end field identifies the last occupied microsecond, so the adapter adds one only when reporting that boundary. Its synchronization clock retains the actual PHY grant timestamp. Link Layer procedures measure `T_IFS = 150 us` from the exclusive end, rather than accidentally scheduling a 149-us gap.

`RADIO_SWITCH_TIME_US` in `bumble.radio_controller.radio` models 60 us of hardware preparation when changing channel, PHY, or TX/RX direction. No transmission or reception can start during that interval. Existing idle time, including T_IFS and T_MAFS, absorbs this preparation rather than extending the protocol spacing. Consecutive primary advertising packets include the switching gap; their AuxPtr offsets and event budgets include it as well. The scheduler reserves preparation time before connection and periodic anchors. Repeated reception on the same channel and PHY does not restart the switching interval. This is a radio implementation parameter, not a Bluetooth specification constant.

The lower RF tester uses `BabbleSimRadio(switch_time_us=0)` to inject and observe packets without the DUT's hardware switching delay. The Controller keeps the default 60-us model. Disabling the tester's delay does not change the DUT's timing constraints or the protocol assertions, and PHY operations still follow simulation time and execute sequentially.

Advertising requests, scan responses and auxiliary connection responses use a bounded synchronization window around `T_IFS`, with a 2-us response-start tolerance. The search deadline includes the selected PHY's preamble/Access Address duration because BabbleSim must complete synchronization before it reports an acquired packet. Once acquired, reception continues through the full packet even beyond that search deadline. Without a response, the radio can switch to the next operation as soon as the search expires. Scheduling reservations still cover the complete permitted request/response exchange, not just the search window.

## Multiple Controllers in One Process

`examples/run_radio_device.py` runs a complete scenario with multiple Hosts and Controllers in one Python process. Hosts share the main asyncio event loop; each Controller runs in its own thread with a `ControllerEventLoop` bound to that radio's simulation clock. Each radio owns its device ID, registration lock and FIFO descriptors. A Controller waiting for PHY does not prevent another Controller thread from submitting the transmission that completes its receive.

The session registers one additional Host clock endpoint. It participates in PHY synchronization and controls Host asyncio timers; it is not another process or a radio. Each Controller keeps its own radio time, independently of the Host clock. The sample assigns Controller IDs from zero and gives the next ID to the Host clock. Two Controllers sharing one session therefore use a PHY with `-D=3`.

Multiple Controller instances have independent radios. Multiple connections on one Controller instead share its radio and scheduling budget; its eight ACL slots are shared between Central and Peripheral roles.

Each Controller owns a random generator seeded from its public address. Central connections allocate a valid Access Address, a 24-bit CRCInit and a Hop Increment in the range 5-16 immediately before sending their connection request. Periodic trains allocate their Access Address and CRCInit when enabled. Configuration templates do not allocate wire identities; Peripheral connections and periodic receivers use the parameters received from their peer. The same generator supplies advertising delay, scan backoff and simulated encryption randomness. Reset restores its initial seed, so identical input and execution order reproduce the sequence. Primary advertising uses the specification's fixed Access Address and CRCInit; hardware timing, clock accuracy and Host-selected parameters are not randomized. Initial simultaneous transmissions may still collide; reception depends on the PHY's normal channel and modem model.

## Run the Samples

After [environment setup](#environment-setup), select a complete Host scenario from the Bumble checkout:

```sh
export BSIM_OUT_PATH=/path/to/babble-workspace/bsim
python -m examples.run_radio_device advertising
python -m examples.run_radio_device connection
python -m examples.run_radio_device periodic
python -m examples.run_radio_device coexistence
```

Each invocation starts its own PHY, configures normal Bumble Devices through Host APIs and stops all participants on completion or failure. It does not use pytest or the protocol-test peer. Public addresses start at `F0:F1:F2:F3:F4:01`; advertising data identifies each Device by name.

| Scenario | Behavior |
|---|---|
| `advertising` | Advertise and scan; verify every selected advertiser's address and exact data. `--advertisers 8` runs eight transmitters and one observer. |
| `connection` | Connect Central and Peripheral, exchange ATT MTU, discover a service and characteristic, read and verify 60 bytes, then disconnect. |
| `periodic` | Start extended and periodic advertising, establish synchronization and verify five periodic reports. `--phy 2m` or `--phy coded` selects the secondary/periodic PHY. |
| `coexistence` | Keep two Central and two Peripheral ACLs on one hub while scanning, transmitting periodic advertising and synchronizing to a peer. Perform ten GATT reads per link and receive five reports in both directions; disconnect one link and check the remaining links and synchronization state. `--links-per-role 4` fills all eight ACL slots. |

For example, exercise the maximum ACL count or Coded periodic traffic:

```sh
python -m examples.run_radio_device coexistence --links-per-role 4
python -m examples.run_radio_device coexistence --phy coded
```

For `periodic` and `coexistence`, `--phy` selects the secondary extended-advertising and periodic PHY. ACL connections in these examples stay on LE 1M; selecting `--phy 2m` or `--phy coded` does not request an ACL PHY update. The coexistence checks cover GATT reads, periodic reports in both directions, and continued operation after selectively disconnecting one ACL. They do not test GATT writes.

The sample prints `COMPLETED <scenario> at <time> us` only after its checks succeed. asyncio timeouts follow simulation time. These are executable usage examples, not additional LL.TS/HCI.TS verdicts.

Logs default to `out/radio/<sim_id>/`; `--log-dir` selects a new directory and `-s` sets the simulation ID. The sample records `devices.log`, `phy.log` and each Controller's `hciN.log` with H4 TX/RX bytes. PHY packet dumps remain under `$BSIM_OUT_PATH/results/<sim_id>`, whose path is printed on completion. They can be converted using BabbleSim's [Wireshark conversion tools](https://babblesim.github.io/csv2pcap.html) or [Ellisys conversion instructions](https://babblesim.github.io/import_Ellisys.html).

Independent sample invocations use fresh simulation IDs by default. If setting `--sim-id` and `--log-dir`, choose different values for concurrent runs. Multiple runs have independent PHY processes and simulated RF environments; competing activities inside one Controller still share its single radio.

Ellisys `.bttrp` exports merge transmitter packets from the participating devices. They retain retransmissions and do not establish whether each receiver accepted a packet; use the native RX logs for that check. The reference converter's fixed RSSI field is a placeholder, not a receiver measurement. Coded FEC1/FEC2 transactions must form one exported packet at the original FEC1 start. In Ellisys, import these files through **File > Import > Bluetooth packets**.

## Controller for an External Host

`examples/run_radio_controller.py` exposes a single-client Unix stream socket carrying H4 packets. Unlike the complete scenarios above, it joins an externally managed PHY. For a standalone HCI Reset exchange, start the PHY in one terminal:

```sh
cd "$BSIM_OUT_PATH/bin"
./bs_2G4_phy_v1 -s=bumble_hci -D=2 -defmodem=BLE_simple \
  -channel=multiatt -argschannel -at=45 -argsmain -dump -dump_imm
```

Start the Controller from the Bumble checkout in another terminal:

```sh
python -m examples.run_radio_controller -s bumble_hci -d 0 --clock-id 1 \
  --address F0:F1:F2:F3:F4:01 --hci-socket /tmp/bumble-radio-hci.sock
```

A Bumble Host can use the existing `unix:/tmp/bumble-radio-hci.sock` transport. An external Host must honor the same simulation time domain when exercising timed procedures; connecting a wall-clock Host does not synchronize its timers. An HCI Reset exchange can be checked without a separate clock-aware Host:

```sh
python - <<'PY'
import socket
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.settimeout(5)
    client.connect('/tmp/bumble-radio-hci.sock')
    client.sendall(bytes.fromhex('01030c00'))
    reply = b''
    while len(reply) < 7:
        data = client.recv(7 - len(reply))
        if not data:
            raise RuntimeError('Controller disconnected')
        reply += data
    assert reply == bytes.fromhex('040e0401030c00'), reply.hex()
    print('HCI Reset: Command Complete, success')
PY
```

This probe closes the HCI client and the Controller then exits. For a larger simulation, assign distinct radio/clock IDs and start every participant required by the PHY's `-D` count. The Controller accepts one Host and exits on disconnect; reconnection is not supported by this example. Use an unused socket path.

## Embedding and asyncio

```python
import asyncio
from bumble.host import Host
from bumble.radio_controller.radio_asyncio import RadioEventLoop
from bumble.radio_controller.radio_babblesim import BabbleSimSession
from bumble.radio_controller.radio_thread import RadioControllerWorker

async def main():
    controller = RadioControllerWorker("radio", public_address="F0:F1:F2:F3:F4:01")
    host = Host(controller_source=controller, controller_sink=controller)
    async with BabbleSimSession("simulation-id", [(0, controller)], clock_dev_id=1):
        # Attach a Device to this Host and run normal asynchronous procedures.
        await asyncio.sleep(1)  # One second of Host simulation time.

with asyncio.Runner(loop_factory=RadioEventLoop) as runner:
    runner.run(main())
```

`RadioEventLoop` retains standard asyncio task, callback, timer and I/O behavior. When no work is ready, its selector synchronously submits WAIT through the Host clock instead of waiting in wall time. No Host code executes until that endpoint receives WAIT_END. Controller threads continue independently and never change the Host's clock.

Each worker uses a `ControllerEventLoop` with the same discrete-clock mechanism. Its `loop.time()`, `asyncio.sleep()` and timeout deadlines follow its own radio time. Software-timer WAITs use the existing radio connection, not another PHY device. Before submitting a WAIT, TX or RX transaction:

1. The requesting coroutine awaits an idle gate. asyncio continues processing current ready tasks, nested callbacks and ready I/O without advancing time.
2. The selector admits the transaction only when this work has drained. A software timer preceding a future RF start is serviced first; a timer also shortens an idle WAIT.
3. The transaction blocks that Controller thread until its PHY response is complete. Other Controller and Host threads remain independent. Callback execution does not depend on whether the ACK was already buffered or required a FIFO wait.
4. After updating radio time, asyncio processes newly ready work before admitting the next transaction.

An admitted TX or RX is nonpreemptive. Software timers expiring during it run after the transaction completes; they do not shorten receive windows, alter `T_IFS`, or provide radio-procedure arbitration. Link Layer scheduling continues to use explicit integer-microsecond deadlines. Worker shutdown can interrupt a blocked transaction without executing protocol callbacks during the wait.

`RadioControllerWorker` is an HCI packet source/sink, not a shared Controller object. The Controller and its radio are constructed, used and closed in the worker thread. Host-to-Controller packets enter a thread-safe queue without waking a pending radio request. A worker-owned simulation-time task also consumes this queue during idle lead-ins to future RF operations, so a long AuxPtr cannot defer command processing until that RF operation finishes. Both this task and ordinary HCI consumption run only after PHY returns execution to the Controller. Controller-to-Host packets are submitted with `call_soon_threadsafe()` before the worker's next PHY request. They execute on the Host loop, after its own ACK; worker threads never enter Host protocol processing. LocalLink keeps its existing asynchronous HCI delivery.

Attach the Host before starting the worker, and run Host procedures inside the session. Do not mutate Controller state directly from another thread. Controller HCI processing may wait until the next radio step; thread-safe enqueueing alone is not permission to execute during a pending PHY request.

Both the standalone Host clock and each worker default to a maximum idle step of 1,000 microseconds. Earlier software timers shorten idle steps, while Link Layer deadlines determine intervening RF operations. These are bounds, not fixed ticks or wall-clock polling intervals.

The session connects the workers and Host clock, reaches an initial PHY barrier at time zero, then binds the Host clock. On exit it unbinds the event loop, stops and joins all worker threads, and finally disconnects the Host clock. Keeping the clock connected until the workers stop prevents additional radio progress during teardown. Thread startup and execution failures propagate to the session owner. The Host WAIT has a 180-second wall-clock watchdog; a stalled PHY cannot be detected using a simulation-time timeout.

When embedding in a runtime that already supplies a synchronized Host event loop and PHY clock endpoint, omit `clock_dev_id`. The session then manages only Controller threads and does not create a clock, bind or replace the caller's event loop. The caller must include those radio device IDs in its PHY topology and establish the shared startup barrier before running Host procedures. The worker does not require `RadioEventLoop`.


## Testing

```sh
python -m pytest tests/radio_controller/unit/ -v
```

The test suites separate Controller implementation checks in `tests/radio_controller/unit/` from protocol verification in `qualification/`. Unit files follow the modules in `bumble/radio_controller/`; `tests/radio_controller/unit/README.md` describes the retained invariants. They protect algorithms and implementation boundaries that HCI/LL procedures cannot reliably expose: nonce exhaustion, wrapping instants, prospective PHY budgets, queue and credit ownership, radio reservation conflicts, shared public buffers, fragmented FIFO I/O and thread/clock admission. Fixtures and RF doubles belong to `unit/`; unit tests do not import or test qualification code. These implementation checks require no native PHY.

The protocol verification suite in `tests/radio_controller/qualification/` uses serialized HCI to configure the DUT; an independent raw-PDU peer checks packets, field values and RF timing. Capability expectations do not read DUT implementation constants. The registrations contain 109 HCI and 392 LL entries against HCI.TS.p39 and LL.TS.p28. Cases are grouped by their actual normative procedure sections, not printed pages or implementation similarity. Each registration records the Test Purpose as a comment and the workbook description of each case. Procedure docstrings retain initial conditions, ordered steps, pass verdicts and source locations. Both HCI and LL chapters use `PROCEDURES |= procedure_cases(...)` with explicit per-case parameters and marks. Successful unlabelled procedures receive a `PASS` protocol verdict; labelled procedures receive `PARTIAL`. The independent `limited` label denotes only sub-microsecond precision and requires execution of a 1-us approximation; `source_conflict` denotes unresolved source requirements and may coexist with `limited`. Only the independent source conflict permits a labelled procedure to skip. See `tests/radio_controller/qualification/README.md` for the chapter map, registration format and execution limits. These independently implemented tests do not constitute Bluetooth qualification.

```sh
export BSIM_OUT_PATH=/path/to/babble-workspace/bsim
python -m pytest tests/radio_controller/ -v -rs
```

Implementation unit tests also cover deferred requests, response-timer ownership and peer-capability caching. Protocol coverage, source corrections and unresolved requirements are recorded in the chapter registrations and procedure docstrings. Collection and execution require no separate test-plan JSON, workbook or review report.

### Parallel Test Execution

Install [pytest-xdist](https://pytest-xdist.readthedocs.io/en/stable/distribution.html) to distribute independent cases across worker processes:

```sh
python -m pip install pytest-xdist
export BSIM_OUT_PATH=/path/to/babble-workspace/bsim
python -m pytest tests/radio_controller/ -n auto --dist worksteal -q -rs

# Run only the selected HCI/LL procedures.
python -m pytest tests/radio_controller/qualification/ -n auto --dist worksteal -q -rs
```

Each native case starts its own PHY process with a fresh simulation ID, FIFO namespace and results directory. pytest supplies separate temporary directories for cases and workers. Equal RF channels, device addresses or random seeds in different simulations do not couple those environments. Separate pytest invocations must also use different directories if explicitly setting `--basetemp`.

`-n auto` selects the worker count for the host; `-n 4` selects it explicitly. `--dist worksteal` lets idle workers take pending cases from other workers, which helps when many short unit checks share a run with long protocol procedures. One case and its participating radios still execute together; xdist does not split its protocol steps across workers.

Some procedures require hundreds of complete advertising observations or repeated control-PDU trials with specified silence windows. Simulation time is advanced through Python/FIFO/PHY exchanges, so these checks still take wall-clock time. Native packet dumps add work, and worker processes share CPU, memory and storage. Increasing the worker count does not eliminate the longest individual cases or the transport's wall-clock watchdogs. Source conflicts and ICS applicability retain their existing skip rules; timing-only `limited` cases must execute at the documented 1-us approximation.

Complete Host workflows and multi-role coexistence are demonstrated by the [samples](#run-the-samples), separately from implementation checks and protocol verdicts.
