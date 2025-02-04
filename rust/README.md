# What is this?

Rust wrappers around the [Bumble](https://github.com/google/bumble) Python API.

Method calls are mapped to the equivalent Python, and return types adapted where
relevant.

See the CLI in `src/main.rs` or the `examples` directory for how to use the
Bumble API.

# Usage

Set up a virtualenv for Bumble, or otherwise have an isolated Python environment
for Bumble and its dependencies.

Due to Python being
[picky about how its sys path is set up](https://github.com/PyO3/pyo3/issues/1741,
it's necessary to explicitly point to the virtualenv's `site-packages`. Use
suitable virtualenv paths as appropriate for your OS, as seen here running
the `battery_client` example:

```
PYTHONPATH=..:~/.virtualenvs/bumble/lib/python3.10/site-packages/ \
    cargo run --example battery_client -- \
    --transport android-netsim --target-addr F0:F1:F2:F3:F4:F5
```

Run the corresponding `battery_server` Python example, and launch an emulator in
Android Studio (currently, Canary is required) to run netsim.

# CLI

Explore the available subcommands:

```
PYTHONPATH=..:[virtualenv site-packages] \
    cargo run --features bumble-tools --bin bumble -- --help
```

Notable subcommands:

- `firmware realtek download`: download Realtek firmware for various chipsets so that it can be automatically loaded when needed
- `usb probe`: show USB devices, highlighting the ones usable for Bluetooth

# Development

Run the tests:

```
PYTHONPATH=.. cargo test
```

Check lints:

```
cargo clippy --all-targets
```

## Code gen

To have the fastest startup while keeping the build simple, code gen for
assigned numbers is done with the `gen_assigned_numbers` tool. It should
be re-run whenever the Python assigned numbers are changed. To ensure that the
generated code is kept up to date, the Rust data is compared to the Python
in tests at `pytests/assigned_numbers.rs`.

To regenerate the assigned number tables based on the Python codebase:

```
PYTHONPATH=.. cargo run --bin gen-assigned-numbers --features dev-tools
```

## HCI packets

Sending a command packet from a device is composed to of two major steps.
There are more generalized ways of dealing with packets in other scenarios.

### Construct the command
Pick a command from `src/internal/hci/packets.pdl` and construct its associated "builder" struct.

```rust
// The "LE Set Scan Enable" command can be found in the Core Bluetooth Spec.
// It can also be found in `packets.pdl` as `packet LeSetScanEnable : Command`
fn main() {
    let device = init_device_as_desired();
    
    let le_set_scan_enable_command_builder = LeSetScanEnableBuilder {
        filter_duplicates: Enable::Disabled,
        le_scan_enable: Enable::Enabled,
    };
}
```

### Send the command and interpret the event response
Send the command from an initialized device, and then receive the response.

```rust
fn main() {
    // ...
    
    // `check_result` to false to receive the event response even if the controller returns a failure code
    let event = device.send_command(le_set_scan_enable_command_builder.into(), /*check_result*/ false);
    // Coerce the event into the expected format. A `Command` should have an associated event response
    // "<command name>Complete".
    let le_set_scan_enable_complete_event: LeSetScanEnableComplete = event.try_into().unwrap();
}
```

### Generic packet handling
At the very least, you should expect to at least know _which_ kind of base packet you are dealing with. Base packets in 
`packets.pdl` can be identified because they do not extend any other packet. They are easily found with the regex:
`^packet [^:]* \{`. For Bluetooth LE (BLE) HCI, one should find some kind of header preceding the packet with the purpose of
packet disambiguation. We do some of that disambiguation for H4 BLE packets using the `WithPacketHeader` trait at `internal/hci/mod.rs`.

Say you've identified a series of bytes that are certainly an `Acl` packet. They can be parsed using the `Acl` struct.
```rust
fn main() {
    let bytes = bytes_that_are_certainly_acl();
    let acl_packet = Acl::parse(bytes).unwrap();
}
```

Since you don't yet know what kind of `Acl` packet it is, you need to specialize it and then handle the various
potential cases.
```rust
fn main() {
    // ...
    match acl_packet.specialize() {
        Payload(bytes) => do_something(bytes),
        None => do_something_else(),
    }
}
```

Some packets may yet further embed other packets, in which case you may need to further specialize until no more
specialization is needed.
