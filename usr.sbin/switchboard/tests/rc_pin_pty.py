#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# rc_pin_pty.py: the far end of a terminal line for getty_test (SR0 of
# switchboard-init-rescope.md).
#
# usage: python3 rc_pin_pty.py [LOG]
#
# It opens a pseudo-terminal, prints the terminal's name relative to /dev
# (for an /etc/ttys entry) and then relays: what it reads on its standard
# input is typed on the line, and what the line's sessions write is copied
# to its standard output.  It keeps the terminal side open as well, so the
# line persists between sessions (a getty respawn) and reading the
# controlling side never reaches end of file; it exits when its standard
# input does.  With LOG, it also appends what the line wrote there, for the
# test's diagnostics.  It waits on select(2), never on a timer.

import os
import select
import sys
import tty


def main(argv):
    log = open(argv[1], "ab", buffering=0) if len(argv) > 1 else None
    master, slave = os.openpty()
    tty.setraw(slave)
    name = os.ttyname(slave)
    sys.stdout.write(name[len("/dev/"):] + "\n")
    sys.stdout.flush()
    out, inp = sys.stdout.fileno(), sys.stdin.fileno()
    while True:
        ready, _, _ = select.select([master, inp], [], [])
        if inp in ready:
            data = os.read(inp, 4096)
            if not data:
                return 0
            os.write(master, data)
        if master in ready:
            try:
                data = os.read(master, 4096)
            except OSError:
                continue
            os.write(out, data)
            if log is not None:
                log.write(data)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
