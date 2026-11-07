# SPDX-License-Identifier: BSD-2-Clause
"""Answer absolute-position/DSR probes using the declared serial terminal size.

This handles the standard cursor-to-bottom-right size probe, not a general screen
emulator. Bare DSR requests and other escape sequences receive no invented answer.
"""
import re


class TerminalSizeResponder:
    query = re.compile(rb"\x1b\[([0-9]{1,6});([0-9]{1,6})[Hf]\x1b\[6n")

    def __init__(self, rows, columns):
        if any(type(value) is not int or not 1 <= value <= 65535
               for value in (rows, columns)):
            raise ValueError("positive 16-bit terminal dimensions required")
        self.rows, self.columns = rows, columns
        self.tail = b""
        self.responses = 0

    def feed(self, chunk):
        data = self.tail + chunk
        replies = []
        for match in self.query.finditer(data):
            if match.end() <= len(self.tail):
                continue  # A complete query answered in the previous chunk.
            row = min(self.rows, max(1, int(match.group(1))))
            column = min(self.columns, max(1, int(match.group(2))))
            replies.append(f"\x1b[{row};{column}R".encode())
            self.responses += 1
        self.tail = data[-64:]
        return replies
