# Copyright 2025 Google LLC
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

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from __future__ import annotations

import asyncio
import abc
from concurrent.futures import ThreadPoolExecutor
import dataclasses
import enum
import logging
import pathlib
from typing import (
    AsyncGenerator,
    BinaryIO,
    TYPE_CHECKING,
)
import sys
import wave

from bumble.colors import color

if TYPE_CHECKING:
    import sounddevice  # type: ignore[import-untyped]


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Classes
# -----------------------------------------------------------------------------
@dataclasses.dataclass
class PcmFormat:
    class Endianness(enum.Enum):
        LITTLE = 0
        BIG = 1

    class SampleType(enum.Enum):
        FLOAT32 = 0
        INT16 = 1

    endianness: Endianness
    sample_type: SampleType
    sample_rate: int
    channels: int

    @classmethod
    def from_str(cls, format_str: str) -> PcmFormat:
        endianness = cls.Endianness.LITTLE  # Others not yet supported.
        sample_type_str, sample_rate_str, channels_str = format_str.split(',')
        if sample_type_str == 'int16le':
            sample_type = cls.SampleType.INT16
        elif sample_type_str == 'float32le':
            sample_type = cls.SampleType.FLOAT32
        else:
            raise ValueError(f'sample type {sample_type_str} not supported')
        sample_rate = int(sample_rate_str)
        channels = int(channels_str)

        return cls(endianness, sample_type, sample_rate, channels)

    @property
    def bytes_per_sample(self) -> int:
        return 2 if self.sample_type == self.SampleType.INT16 else 4


def check_audio_output(output: str) -> bool:
    if output == 'device' or output.startswith('device:'):
        try:
            import sounddevice
        except ImportError as exc:
            raise ValueError(
                'audio output not available (sounddevice python module not installed)'
            ) from exc
        except OSError as exc:
            raise ValueError(
                'audio output not available '
                '(sounddevice python module failed to load: '
                f'{exc})'
            ) from exc

        if output == 'device':
            # Default device
            return True

        # Specific device
        device = output[7:]
        if device == '?':
            print(color('Audio Devices:', 'yellow'))
            for device_info in [
                device_info
                for device_info in sounddevice.query_devices()
                if device_info['max_output_channels'] > 0
            ]:
                device_index = device_info['index']
                is_default = (
                    color(' [default]', 'green')
                    if sounddevice.default.device[1] == device_index
                    else ''
                )
                print(
                    f'{color(device_index, "cyan")}: {device_info["name"]}{is_default}'
                )
            return False

        try:
            device_info = sounddevice.query_devices(int(device))
        except sounddevice.PortAudioError as exc:
            raise ValueError('No such audio device') from exc

        if device_info['max_output_channels'] < 1:
            raise ValueError(
                f'Device {device} ({device_info["name"]}) does not have an output'
            )

    return True


async def create_audio_output(output: str) -> AudioOutput:
    if output == 'stdout':
        return StreamAudioOutput(sys.stdout.buffer)

    if output == 'device' or output.startswith('device:'):
        device_name = '' if output == 'device' else output[7:]
        return SoundDeviceAudioOutput(device_name)

    if output == 'ffplay':
        return SubprocessAudioOutput(
            command=(
                'ffplay -probesize 32 -fflags nobuffer -analyzeduration 0 '
                '-ar {sample_rate} '
                '-ch_layout {channel_layout} '
                '-f f32le pipe:0'
            )
        )

    if output.startswith('file:'):
        return FileAudioOutput(output[5:])

    raise ValueError('unsupported audio output')


class AudioOutput(abc.ABC):
    """Audio output to which PCM samples can be written."""

    async def open(self, pcm_format: PcmFormat) -> None:
        """Start the output."""

    @abc.abstractmethod
    def write(self, pcm_samples: bytes) -> None:
        """Write PCM samples. Must not block."""

    async def aclose(self) -> None:
        """Close the output."""


class ThreadedAudioOutput(AudioOutput):
    """Base class for AudioOutput classes that may need to call blocking functions.

    The actual writing is performed in a thread, so as to ensure that calling write()
    does not block the caller.
    """

    def __init__(self) -> None:
        self._thread_pool = ThreadPoolExecutor(1)
        self._pcm_samples: asyncio.Queue[bytes] = asyncio.Queue()
        self._write_task = asyncio.create_task(self._write_loop())

    async def _write_loop(self) -> None:
        while True:
            pcm_samples = await self._pcm_samples.get()
            await asyncio.get_running_loop().run_in_executor(
                self._thread_pool, self._write, pcm_samples
            )

    @abc.abstractmethod
    def _write(self, pcm_samples: bytes) -> None:
        """This method does the actual writing and can block."""

    def write(self, pcm_samples: bytes) -> None:
        self._pcm_samples.put_nowait(pcm_samples)

    def _close(self) -> None:
        """This method does the actual closing and can block."""

    async def aclose(self) -> None:
        await asyncio.get_running_loop().run_in_executor(self._thread_pool, self._close)
        self._write_task.cancel()
        self._thread_pool.shutdown()


class SoundDeviceAudioOutput(ThreadedAudioOutput):
    def __init__(self, device_name: str) -> None:
        super().__init__()
        self._device = int(device_name) if device_name else None
        self._stream: sounddevice.RawOutputStream | None = None

    async def open(self, pcm_format: PcmFormat) -> None:
        import sounddevice  # pylint: disable=import-error

        self._stream = sounddevice.RawOutputStream(
            samplerate=pcm_format.sample_rate,
            device=self._device,
            channels=pcm_format.channels,
            dtype='float32',
        )
        self._stream.start()

    def _write(self, pcm_samples: bytes) -> None:
        if self._stream is None:
            return

        try:
            self._stream.write(pcm_samples)
        except Exception as error:
            print(f'Sound device error: {error}')
            raise

    def _close(self):
        self._stream.stop()
        self._stream = None


class StreamAudioOutput(ThreadedAudioOutput):
    """AudioOutput where PCM samples are written to a stream that may block."""

    def __init__(self, stream: BinaryIO) -> None:
        super().__init__()
        self._stream = stream

    def _write(self, pcm_samples: bytes) -> None:
        self._stream.write(pcm_samples)
        self._stream.flush()


class FileAudioOutput(StreamAudioOutput):
    """AudioOutput where PCM samples are written to a file."""

    def __init__(self, filename: str) -> None:
        self._file = open(filename, "wb")
        super().__init__(self._file)

    async def shutdown(self):
        self._file.close()
        return await super().shutdown()


class SubprocessAudioOutput(AudioOutput):
    """AudioOutput where audio samples are written to a subprocess via stdin."""

    def __init__(self, command: str) -> None:
        self._command = command
        self._subprocess: asyncio.subprocess.Process | None

    async def open(self, pcm_format: PcmFormat) -> None:
        if pcm_format.channels == 1:
            channel_layout = 'mono'
        elif pcm_format.channels == 2:
            channel_layout = 'stereo'
        else:
            raise ValueError(f'{pcm_format.channels} channels not supported')

        command = self._command.format(
            sample_rate=pcm_format.sample_rate, channel_layout=channel_layout
        )
        self._subprocess = await asyncio.create_subprocess_shell(
            command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    def write(self, pcm_samples: bytes) -> None:
        if self._subprocess is None or self._subprocess.stdin is None:
            return

        self._subprocess.stdin.write(pcm_samples)

    async def aclose(self):
        if self._subprocess:
            self._subprocess.terminate()


def check_audio_input(input: str) -> bool:
    if input == 'device' or input.startswith('device:'):
        try:
            import sounddevice  # pylint: disable=import-error
        except ImportError as exc:
            raise ValueError(
                'audio input not available (sounddevice python module not installed)'
            ) from exc
        except OSError as exc:
            raise ValueError(
                'audio input not available '
                '(sounddevice python module failed to load: '
                f'{exc})'
            ) from exc

        if input == 'device':
            # Default device
            return True

        # Specific device
        device = input[7:]
        if device == '?':
            print(color('Audio Devices:', 'yellow'))
            for device_info in [
                device_info
                for device_info in sounddevice.query_devices()
                if device_info['max_input_channels'] > 0
            ]:
                device_index = device_info["index"]
                is_mono = device_info['max_input_channels'] == 1
                max_channels = color(f'[{"mono" if is_mono else "stereo"}]', 'cyan')
                is_default = (
                    color(' [default]', 'green')
                    if sounddevice.default.device[0] == device_index
                    else ''
                )
                print(
                    f'{color(device_index, "cyan")}: {device_info["name"]}'
                    f' {max_channels}{is_default}'
                )
            return False

        try:
            device_info = sounddevice.query_devices(int(device))
        except sounddevice.PortAudioError as exc:
            raise ValueError('No such audio device') from exc

        if device_info['max_input_channels'] < 1:
            raise ValueError(
                f'Device {device} ({device_info["name"]}) does not have an input'
            )

    return True


async def create_audio_input(input: str, input_format: str) -> AudioInput:
    pcm_format: PcmFormat | None
    if input_format == 'auto':
        pcm_format = None
    else:
        pcm_format = PcmFormat.from_str(input_format)

    if input == 'stdin':
        if not pcm_format:
            raise ValueError('input format details required for stdin')
        return StreamAudioInput(sys.stdin.buffer, pcm_format)

    if input == 'device' or input.startswith('device:'):
        if not pcm_format:
            raise ValueError('input format details required for device')
        device_name = '' if input == 'device' else input[7:]
        return SoundDeviceAudioInput(device_name, pcm_format)

    # If there's no file: prefix, check if we can assume it is a file.
    if pathlib.Path(input).is_file():
        input = 'file:' + input

    if input.startswith('file:'):
        filename = input[5:]
        if filename.endswith('.wav'):
            if input_format != 'auto':
                raise ValueError(".wav file only supported with 'auto' format")
            return WaveAudioInput(filename)

        if pcm_format is None:
            raise ValueError('input format details required for raw PCM files')
        return FileAudioInput(filename, pcm_format)

    raise ValueError('input not supported')


class AudioInput(abc.ABC):
    """Audio input that produces PCM samples."""

    @abc.abstractmethod
    async def open(self) -> PcmFormat:
        """Open the input."""

    @abc.abstractmethod
    def frames(self, frame_size: int) -> AsyncGenerator[bytes]:
        """Generate one frame of PCM samples. Must not block."""

    async def aclose(self) -> None:
        """Close the input."""


class ThreadedAudioInput(AudioInput):
    """Base class for AudioInput implementation where reading samples may block."""

    def __init__(self) -> None:
        self._thread_pool = ThreadPoolExecutor(1)
        self._pcm_samples: asyncio.Queue[bytes] = asyncio.Queue()

    @abc.abstractmethod
    def _read(self, frame_size: int) -> bytes:
        pass

    @abc.abstractmethod
    def _open(self) -> PcmFormat:
        pass

    def _close(self) -> None:
        pass

    async def open(self) -> PcmFormat:
        return await asyncio.get_running_loop().run_in_executor(
            self._thread_pool, self._open
        )

    async def frames(self, frame_size: int) -> AsyncGenerator[bytes]:
        while pcm_sample := await asyncio.get_running_loop().run_in_executor(
            self._thread_pool, self._read, frame_size
        ):
            yield pcm_sample

    async def aclose(self) -> None:
        await asyncio.get_running_loop().run_in_executor(self._thread_pool, self._close)
        self._thread_pool.shutdown()


class WaveAudioInput(ThreadedAudioInput):
    """Audio input that reads PCM samples from a .wav file."""

    def __init__(self, filename: str) -> None:
        super().__init__()
        self._filename = filename
        self._wav: wave.Wave_read | None = None
        self._bytes_read = 0

    def _open(self) -> PcmFormat:
        self._wav = wave.open(self._filename, 'rb')
        if self._wav.getsampwidth() != 2:
            raise ValueError('sample width not supported')
        return PcmFormat(
            PcmFormat.Endianness.LITTLE,
            PcmFormat.SampleType.INT16,
            self._wav.getframerate(),
            self._wav.getnchannels(),
        )

    def _read(self, frame_size: int) -> bytes:
        if not self._wav:
            return b''

        pcm_samples = self._wav.readframes(frame_size)
        if not pcm_samples and self._bytes_read:
            # Loop around.
            self._wav.rewind()
            self._bytes_read = 0
            pcm_samples = self._wav.readframes(frame_size)

        self._bytes_read += len(pcm_samples)
        return pcm_samples

    def _close(self) -> None:
        if self._wav:
            self._wav.close()


class StreamAudioInput(ThreadedAudioInput):
    """AudioInput where samples are read from a raw PCM stream that may block."""

    def __init__(self, stream: BinaryIO, pcm_format: PcmFormat) -> None:
        super().__init__()
        self._stream = stream
        self._pcm_format = pcm_format

    def _open(self) -> PcmFormat:
        return self._pcm_format

    def _read(self, frame_size: int) -> bytes:
        return self._stream.read(
            frame_size * self._pcm_format.channels * self._pcm_format.bytes_per_sample
        )


class FileAudioInput(StreamAudioInput):
    """AudioInput where PCM samples are read from a raw PCM file."""

    def __init__(self, filename: str, pcm_format: PcmFormat) -> None:
        self._stream = open(filename, "rb")
        super().__init__(self._stream, pcm_format)

    def _close(self) -> None:
        self._stream.close()


class SoundDeviceAudioInput(ThreadedAudioInput):
    def __init__(self, device_name: str, pcm_format: PcmFormat) -> None:
        super().__init__()
        self._device = int(device_name) if device_name else None
        self._pcm_format = pcm_format
        self._stream: sounddevice.RawInputStream | None = None

    def _open(self) -> PcmFormat:
        import sounddevice  # pylint: disable=import-error

        self._stream = sounddevice.RawInputStream(
            samplerate=self._pcm_format.sample_rate,
            device=self._device,
            channels=self._pcm_format.channels,
            dtype='int16',
        )
        self._stream.start()

        return PcmFormat(
            PcmFormat.Endianness.LITTLE,
            PcmFormat.SampleType.INT16,
            self._pcm_format.sample_rate,
            2,
        )

    def _read(self, frame_size: int) -> bytes:
        if not self._stream:
            return b''
        pcm_buffer, overflowed = self._stream.read(frame_size)
        if overflowed:
            logger.warning("input overflow")

        # Convert the buffer to stereo if needed
        if self._pcm_format.channels == 1:
            stereo_buffer = bytearray()
            for i in range(frame_size):
                sample = pcm_buffer[i * 2 : i * 2 + 2]
                stereo_buffer += sample + sample
            return stereo_buffer

        return bytes(pcm_buffer)

    def _close(self):
        self._stream.stop()
        self._stream = None
