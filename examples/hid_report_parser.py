from bumble.colors import color
from hid_key_map import base_keys, mod_keys, shift_map


# ------------------------------------------------------------------------------
def get_key(modifier: str, key: str) -> str:
    if modifier == '22':
        modifier = '02'
    if modifier in mod_keys:
        modifier = mod_keys[modifier]
    else:
        return ''
    if key in base_keys:
        key = base_keys[key]
    else:
        return ''
    if (modifier == 'left_shift' or modifier == 'right_shift') and key in shift_map:
        key = shift_map[key]

    return key


class Keyboard:
    def __init__(self):  # type: ignore
        self.report = [
            [  # Bit array for Modifier keys
                0,  # Right GUI - (usually the Windows key)
                0,  # Right ALT
                0,  # Right Shift
                0,  # Right Control
                0,  # Left GUI - (usually the Windows key)
                0,  # Left ALT
                0,  # Left Shift
                0,  # Left Control
            ],
            0x00,  # Vendor reserved
            '',  # Rest is space for 6 keys
            '',
            '',
            '',
            '',
            '',
        ]

    def decode_keyboard_report(self, input_report: bytes, report_length: int) -> None:
        if report_length >= 8:
            modifier = input_report[1]
            self.report[0] = [int(x) for x in '{0:08b}'.format(modifier)]
            self.report[0].reverse()  # type: ignore

            modifier_key = str((modifier & 0x22).to_bytes(1, "big").hex())
            keycodes = []
            for k in range(3, report_length):
                keycodes.append(str(input_report[k].to_bytes(1, "big").hex()))
                self.report[k - 1] = get_key(modifier_key, keycodes[k - 3])
        else:
            print(color('Warning: Not able to parse report', 'yellow'))

    def print_keyboard_report(self) -> None:
        print(color('\tKeyboard Input Received', 'green', None, 'bold'))
        print(color(f'Keys:', 'white', None, 'bold'))
        for i in range(1, 7):
            print(
                color(f' Key{i}{" ":>8s}=  ', 'cyan', None, 'bold'), self.report[i + 1]
            )
        print(color(f'\nModifier Keys:', 'white', None, 'bold'))
        print(
            color(f'  Left Ctrl   : ', 'cyan'),
            f'{self.report[0][0] == 1!s:<5}',  # type: ignore
            color(f'  Left Shift  : ', 'cyan'),
            f'{self.report[0][1] == 1!s:<5}',  # type: ignore
            color(f'  Left ALT    : ', 'cyan'),
            f'{self.report[0][2] == 1!s:<5}',  # type: ignore
            color(f'  Left GUI    : ', 'cyan'),
            f'{self.report[0][3] == 1!s:<5}\n',  # type: ignore
            color(f' Right Ctrl  : ', 'cyan'),
            f'{self.report[0][4] == 1!s:<5}',  # type: ignore
            color(f'  Right Shift : ', 'cyan'),
            f'{self.report[0][5] == 1!s:<5}',  # type: ignore
            color(f'  Right ALT   : ', 'cyan'),
            f'{self.report[0][6] == 1!s:<5}',  # type: ignore
            color(f'  Right GUI   : ', 'cyan'),
            f'{self.report[0][7] == 1!s:<5}',  # type: ignore
        )


# ------------------------------------------------------------------------------
class Mouse:
    def __init__(self):  # type: ignore
        self.report = [
            [  # Bit array for Buttons
                0,  # Button 1 (primary/trigger
                0,  # Button 2 (secondary)
                0,  # Button 3 (tertiary)
                0,  # Button 4
                0,  # Button 5
                0,  # unused padding bits
                0,  # unused padding bits
                0,  # unused padding bits
            ],
            0,  # X
            0,  # Y
            0,  # Wheel
            0,  # AC Pan
        ]

    def decode_mouse_report(self, input_report: bytes, report_length: int) -> None:
        self.report[0] = [int(x) for x in '{0:08b}'.format(input_report[1])]
        self.report[0].reverse()  # type: ignore
        self.report[1] = input_report[2]
        self.report[2] = input_report[3]
        if report_length in [5, 6]:
            self.report[3] = input_report[4]
            self.report[4] = input_report[5] if report_length == 6 else 0

    def print_mouse_report(self) -> None:
        print(color('\tMouse Input Received', 'green', None, 'bold'))
        print(
            color(f' Button 1 (primary/trigger) = ', 'cyan'),
            self.report[0][0] == 1,  # type: ignore
            color(f'\n Button 2 (secondary)       = ', 'cyan'),
            self.report[0][1] == 1,  # type: ignore
            color(f'\n Button 3 (tertiary)        = ', 'cyan'),
            self.report[0][2] == 1,  # type: ignore
            color(f'\n Button4                    = ', 'cyan'),
            self.report[0][3] == 1,  # type: ignore
            color(f'\n Button5                    = ', 'cyan'),
            self.report[0][4] == 1,  # type: ignore
            color(f'\n X (X-axis displacement)    = ', 'cyan'),
            self.report[1],
            color(f'\n Y (Y-axis displacement)    = ', 'cyan'),
            self.report[2],
            color(f'\n Wheel                      = ', 'cyan'),
            self.report[3],
            color(f'\n AC PAN                     = ', 'cyan'),
            self.report[4],
        )


# ------------------------------------------------------------------------------
class ReportParser:
    @staticmethod
    def parse_input_report(input_report: bytes) -> None:

        report_id = input_report[0]  # pylint: disable=unsubscriptable-object
        report_length = len(input_report)

        # Keyboard input report (report id = 1)
        if report_id == 1 and report_length >= 8:
            keyboard = Keyboard()  # type: ignore
            keyboard.decode_keyboard_report(input_report, report_length)
            keyboard.print_keyboard_report()
        # Mouse input report (report id = 2)
        elif report_id == 2 and report_length in [4, 5, 6]:
            mouse = Mouse()  # type: ignore
            mouse.decode_mouse_report(input_report, report_length)
            mouse.print_mouse_report()
        else:
            print(color(f'Warning: Parse Error Report ID {report_id}', 'yellow'))
