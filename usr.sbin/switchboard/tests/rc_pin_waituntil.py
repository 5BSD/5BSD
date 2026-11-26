#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# rc_pin_waituntil.py: wait, on file events, until a condition holds.
#
# usage: python3 rc_pin_waituntil.py PATH [PATH ...] -- COMMAND [ARGS ...]
#
# It watches each PATH (a file or a directory; a missing file's directory)
# with kqueue EVFILT_VNODE, then runs COMMAND, and runs it again after each
# event on a PATH, until COMMAND exits 0.  Because the watch is set before
# the first run, a change between a run and the wait is not lost.  It waits
# in kevent(2), never on a timer; its caller's timeout bounds it.  It exits
# with COMMAND's 0.

import os
import select
import subprocess
import sys

FFLAGS = (select.KQ_NOTE_WRITE | select.KQ_NOTE_EXTEND |
          select.KQ_NOTE_ATTRIB | select.KQ_NOTE_RENAME |
          select.KQ_NOTE_DELETE)


def watch(kq, paths):
    fds = []
    for p in paths:
        target = p if os.path.exists(p) else (os.path.dirname(p) or ".")
        fd = os.open(target, os.O_RDONLY)
        kq.control([select.kevent(fd, select.KQ_FILTER_VNODE,
                                  select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                                  FFLAGS)], 0)
        fds.append(fd)
    return fds


def main(argv):
    if "--" not in argv[1:]:
        sys.stderr.write("usage: rc_pin_waituntil.py PATH ... -- COMMAND ...\n")
        return 2
    sep = argv.index("--", 1)
    paths, cmd = argv[1:sep], argv[sep + 1:]
    if not paths or not cmd:
        sys.stderr.write("usage: rc_pin_waituntil.py PATH ... -- COMMAND ...\n")
        return 2
    kq = select.kqueue()
    fds = watch(kq, paths)
    while subprocess.call(cmd) != 0:
        kq.control(None, 1, None)
        # A file that appeared or was replaced: watch the new one.
        for fd in fds:
            os.close(fd)
        kq.close()
        kq = select.kqueue()
        fds = watch(kq, paths)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
