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