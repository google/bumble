AURACAST TOOL
=============

The "auracast" tool implements commands that implement broadcasting, receiving
and controlling LE Audio broadcasts.

=== "Running as an installed package"
    ```
    $ bumble-auracast
    ```

=== "Running from source"
    ```
    $ python3 apps/auracast.py <args>
    ```

# Python Dependencies
Try installing the optional `[auracast]` dependencies:

=== "From source"
    ```bash
    $ python3 -m pip install ".[auracast]"
    ```

=== "From PyPI"
    ```bash
    $ python3 -m pip install "bumble[auracast]"
    ```

## LC3
The `auracast` app depends on the `lc3` python module, which is available
either as PyPI module (currently only available for Linux x86_64).
When installing Bumble with the optional `auracast` dependency, the `lc3`
module will be installed from the `lc3py` PyPI package if available.
If not, you will need to install it separately. This can be done with:
```bash
$ python3 -m pip install "git+https://github.com/google/liblc3.git"
```

## SoundDevice
The `sounddevice` module is required for audio output to the host's sound
output device(s) and/or input from the host's input device(s).
If not installed, the `auracast` app is still functional, but will be limited
to non-device inputs and output (files, external processes, ...)

On macOS and Windows, the `sounddevice` module gets installed with the
native PortAudio libraries included.

For Linux, however, PortAudio must be installed separately.
This is typically done with a command like:
```bash
$ sudo apt install libportaudio2
```

Visit the [sounddevice documentation](https://python-sounddevice.readthedocs.io/)
for details.


# General Usage
```
Usage: bumble-auracast [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  assist    Scan for broadcasts on behalf of an audio server
  pair      Pair with an audio server
  receive   Receive a broadcast source
  scan      Scan for public broadcasts
  transmit  Transmit a broadcast source
```

Use `bumble-auracast <command> --help` to get more detailed usage information
for a specific `<command>`.

## `assist`
Act as a broadcast assistant.

Use `bumble-auracast assist --help` for details on the commands and options.

The assistant commands are:

### `monitor-state`
Subscribe to the state characteristic and monitor changes.

### `add-source`
Add a broadcast source. This will instruct the device to start
receiving a broadcast.

### `modify-source`
Modify a broadcast source.

### `remove-source`
Remote a broadcast source.

## `pair`
Pair with a device.

## `receive`
Receive a broadcast source.

The `--output` option specifies where to send the decoded audio samples.
The following outputs are supported:

### Sound Device
The `--output` argument is either `device`, to send the audio to the hosts's default sound device, or `device:<DEVICE_ID>` where `<DEVICE_ID>`
is the integer ID of one of the available sound devices.
When invoked with `--output "device:?"`, a list of available devices and
their IDs is printed out.

### Standard Output
With `--output stdout`, the decoded audio samples are written to the
standard output (currently always as float32 PCM samples)

### FFPlay
With `--output ffplay`, the decoded audio samples are piped to `ffplay`
in a child process. This option is only available if `ffplay` is a command that is available on the host.

### File
With `--output <filename>` or `--output file:<filename>`, the decoded audio
samples are written to a file (currently always as float32 PCM)

## `transmit`
Broadcast an audio source as a transmitter.

The `--input` and `--input-format` options specify what audio input
source to transmit.
The following inputs are supported:

### Sound Device
The `--input` argument is either `device`, to use the host's default sound
device (typically a builtin microphone), or `device:<DEVICE_ID>` where
`<DEVICE_ID>` is the integer ID of one of the available sound devices.
When invoked with `--input "device:?"`, a list of available devices and their
IDs is printed out.

### Standard Input
With `--input stdout`, the audio samples are read from the standard input.
(currently always as int16 PCM).

### File
With `--input <filename>` or `--input file:<filename>`, the audio samples
are read from a .wav or raw PCM file.

Use the `--input-format <FORMAT>` option to specify the format of the audio
samples in raw PCM files. `<FORMAT>` is expressed as:
`<sample-type>,<sample-rate>,<channels>`
(the only supported <sample-type> currently is 'int16le' for 16 bit signed integers with little-endian byte order)

## `scan`
Scan for public broadcasts.

A live display of the available broadcasts is displayed continuously.

# Compatibility With Some Products
The `auracast` app has been tested for compatibility with a few products.
The list is still very limited. Please let us know if there are products
that are not working well, or if there are specific instructions that should
be shared to allow better compatibiity with certain products.

## Transmitters

The `receive` command has been tested to successfully receive broadcasts from
the following transmitters:

  * JBL GO 4
  * Flairmesh FlooGoo FMA120
  * Eppfun AK3040Pro Max
  * HIGHGAZE BA-25T
  * Nexum Audio VOCE and USB dongle

## Receivers

### Pixel Buds Pro 2

The Pixel Buds Pro 2 can be used as a broadcast receiver, controlled by the
`auracast assist` command, instructing the buds to receive a broadcast.

Use the `assist --command add-source` command to tell the buds to receive a
broadcast.

Use the `assist --command monitor-state` command to monitor the current sync/receive
state of the buds.

### JBL
The JBL GO 4 and other JBL products that support the Auracast feature can be used
as transmitters or receivers.

When running in receiver mode (pressing the Auracast button while not already playing),
the JBL speaker will scan for broadcast advertisements with a specific manufacturer data.
Use the `--manufacturer-data` option of the `transmit` command in order to include data
that will let the speaker recognize the broadcast as a compatible source.

The manufacturer ID for JBL is 87.
Using an option like `--manufacturer-data 87:00000000000000000000000000000000dffd` should work (tested on the
JBL GO 4. The `dffd` value at the end of the payload may be different on other models?).


### Others

  * Nexum Audio VOCE and USB dongle