# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard
"""Serial terminal protocol regression: arbitrary pipe fragmentation and bounds."""
import unittest
from serial_terminal import TerminalSizeResponder


class TerminalProtocol(unittest.TestCase):
    def test_size_probe_at_every_fragment_boundary(self):
        probe = b"\x1b7\x1b[r\x1b[999;999H\x1b[6n\x1b8"
        for boundary in range(len(probe)+1):
            with self.subTest(boundary=boundary):
                terminal = TerminalSizeResponder(24,80)
                self.assertEqual(terminal.feed(probe[:boundary]) +
                                 terminal.feed(probe[boundary:]), [b"\x1b[24;80R"])
                self.assertEqual(terminal.feed(b"ordinary login output"), [])
                self.assertEqual(terminal.responses, 1)
        terminal = TerminalSizeResponder(40,120)
        self.assertEqual([reply for byte in probe for reply in terminal.feed(bytes([byte]))],
                         [b"\x1b[40;120R"])

    def test_position_bounds_and_no_answer_for_unknown_cursor(self):
        terminal = TerminalSizeResponder(24,80)
        self.assertEqual(terminal.feed(b"text\x1b[6n"), [])
        self.assertEqual(terminal.feed(b"\x1b[0;0f\x1b[6n\x1b[2;10H\x1b[6n"),
                         [b"\x1b[1;1R", b"\x1b[2;10R"])
        for dimensions in ((0,80),(24,-1),(True,80),(24,65536)):
            with self.subTest(dimensions=dimensions), self.assertRaises(ValueError):
                TerminalSizeResponder(*dimensions)


if __name__ == "__main__":
    unittest.main()
