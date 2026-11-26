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
# to its standard output (and appended to LOG, for the test's diagnostics).
# It holds the controlling side, so the line persists between sessions.
#
# Between sessions the terminal side has no opener (getty revokes it when a
# session ends), and reading the controlling side then gives end of file
# (an empty read, or EIO).  The controlling side is watched with an
# edge-triggered kqueue EVFILT_READ (EV_CLEAR) and read without blocking,
# so such an end of file is read once and the next event is the next
# session's output: it never spins.  It exits when its standard input
# reaches end of file.  It waits in kevent(2), never on a timer.

import errno
import os
import select
import sys
import tty


def drain(master, out, log):
    """Copy what the line wrote; stop at no data, end of file or EIO."""
    while True:
        try:
            data = os.read(master, 4096)
        except BlockingIOError:
            return
        except OSError as e:
            if e.errno == errno.EIO:
                return
            raise
        if not data:
            return
        os.write(out, data)
        if log is not None:
            log.write(data)


def main(argv):
    log = open(argv[1], "ab", buffering=0) if len(argv) > 1 else None
    master, slave = os.openpty()
    tty.setraw(slave)
    name = os.ttyname(slave)
    os.close(slave)
    os.set_blocking(master, False)
    sys.stdout.write(name[len("/dev/"):] + "\n")
    sys.stdout.flush()
    out, inp = sys.stdout.fileno(), sys.stdin.fileno()
    kq = select.kqueue()
    kq.control([
        select.kevent(master, select.KQ_FILTER_READ,
                      select.KQ_EV_ADD | select.KQ_EV_CLEAR),
        select.kevent(inp, select.KQ_FILTER_READ, select.KQ_EV_ADD),
    ], 0)
    while True:
        for ev in kq.control(None, 2, None):
            if ev.ident == inp:
                data = os.read(inp, 4096)
                if not data:
                    return 0
                os.write(master, data)
            else:
                drain(master, out, log)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
