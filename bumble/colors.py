# Copyright (c) 2012 Giorgos Verigakis <verigak@gmail.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from functools import partial
from typing import List, Optional, Union


# ANSI color names. There is also a "default"
COLORS = ('black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white')

# ANSI style names
STYLES = (
    'none',
    'bold',
    'faint',
    'italic',
    'underline',
    'blink',
    'blink2',
    'negative',
    'concealed',
    'crossed',
)


ColorSpec = Union[str, int]


def _join(*values: ColorSpec) -> str:
    return ';'.join(str(v) for v in values)


def _color_code(spec: ColorSpec, base: int) -> str:
    if isinstance(spec, str):
        spec = spec.strip().lower()

    if spec == 'default':
        return _join(base + 9)
    elif spec in COLORS:
        return _join(base + COLORS.index(spec))
    elif isinstance(spec, int) and 0 <= spec <= 255:
        return _join(base + 8, 5, spec)
    else:
        raise ValueError('Invalid color spec "%s"' % spec)


def color(
    s: str,
    fg: Optional[ColorSpec] = None,
    bg: Optional[ColorSpec] = None,
    style: Optional[str] = None,
) -> str:
    codes: List[ColorSpec] = []

    if fg:
        codes.append(_color_code(fg, 30))
    if bg:
        codes.append(_color_code(bg, 40))
    if style:
        for style_part in style.split('+'):
            if style_part in STYLES:
                codes.append(STYLES.index(style_part))
            else:
                raise ValueError('Invalid style "%s"' % style_part)

    if codes:
        return '\x1b[{0}m{1}\x1b[0m'.format(_join(*codes), s)
    else:
        return s


# Foreground color shortcuts
black = partial(color, fg='black')
red = partial(color, fg='red')
green = partial(color, fg='green')
yellow = partial(color, fg='yellow')
blue = partial(color, fg='blue')
magenta = partial(color, fg='magenta')
cyan = partial(color, fg='cyan')
white = partial(color, fg='white')

# Style shortcuts
bold = partial(color, style='bold')
none = partial(color, style='none')
faint = partial(color, style='faint')
italic = partial(color, style='italic')
underline = partial(color, style='underline')
blink = partial(color, style='blink')
blink2 = partial(color, style='blink2')
negative = partial(color, style='negative')
concealed = partial(color, style='concealed')
crossed = partial(color, style='crossed')
