#!/usr/bin/env python3
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# vm-monitor.py -- watch a vm-provider.sh guest until QEMU exits.
#
# usage: vm-monitor.py --pid PID --log SERIAL_LOG --deadline EPOCH
#            --fatal REGEX --known KNOWN_LOR [--fatal-lor yes|no]
#            [--grace SECONDS]
#        vm-monitor.py --has-unknown-lor SERIAL_LOG KNOWN_LOR
#
# The first form waits, without polling, on three events through one
# kqueue: QEMU's exit (EVFILT_PROC NOTE_EXIT), writes to the serial log
# (EVFILT_VNODE NOTE_WRITE|NOTE_EXTEND) and the deadline (the kevent
# timeout).  Each write is read and checked: a line matching --fatal, or
# (unless --fatal-lor no) a complete WITNESS lock order reversal report that
# matches no known-lor.txt entry, is a problem.  On a problem it prints
# "KERNEL/INIT PROBLEM in serial log", lets the guest finish printing for at
# most the grace period (ending at once if QEMU exits), then sends QEMU
# SIGTERM unless it has already exited ("qemu had already exited").  At the
# deadline it prints TIMEOUT and does the same without the grace.  It
# returns only after QEMU has exited.
#
# Exit status: 0, QEMU exited by itself with no problem seen; 3, stopped for
# a problem; 4, stopped at the deadline; 5, QEMU had exited before the
# monitor could watch it (the run is not clean); 2, usage or setup failure
# (the caller must then stop QEMU itself).
#
# The second form reads a whole serial log after the run: exit 0 when some
# reversal report matches no known-lor.txt entry, 1 when none does, 2 when
# the log or the list cannot be read (the caller must count that as an
# unknown reversal).  Both forms classify a report the same way: the text
# after "lock order reversal:" through the end of its "attempted at" stack
# (the syscall or kernel-thread entry frame), or up to the next report or the
# first line that is not part of a report, against each entry with
# re.search.  There is no line cap: a multi-hop report ("All lock orders
# from ...") lists every hop's stack before the attempted one, and an entry
# must be able to require frames of that last stack.

import errno
import os
import re
import select
import signal
import sys
import time

# After a fatal console line the kernel is still printing the rest of the
# report (a panic's backtrace, "cpuid =", the dump attempt) or is about to
# power off.  Keep QEMU this long so those lines reach the serial log; the
# wait ends as soon as QEMU exits.  Five seconds covers the panic and
# shutdown output of the recorded TCG guest runs, which print within one or
# two seconds of the first fatal line.
FATAL_GRACE_S = 5.0

HEADER = "lock order reversal:"
# Lines that belong to a WITNESS reversal report (after the header).
# The frame that ends a kernel stack in a report: syscall or thread entry.
# amd64: the 64-bit syscall entry, the ia32 int 0x80 entry (IDTVEC: X
# prefix; int0x80_syscall_common), kernel threads; arm64: the EL0 exception
# vectors (handle_el0_sync and the rest) and fork_trampoline.
STACK_END = re.compile(r"^#\d+ \S+ at (fast_syscall_common|Xfast_syscall|X?int0x80_syscall\w*|handle_el0_\w+|fork_trampoline|fork_exit)\+")
REPORT_LINE = re.compile(r'^(\s*$| 1st | 2nd | 3rd |lock order |All lock orders|"|#\d+ )')


def load_known(path):
    try:
        with open(path) as f:
            return [re.compile(l.strip()) for l in f
                    if l.strip() and not l.lstrip().startswith("#")]
    except OSError:
        return []


def is_known(block, pats):
    return any(p.search(block) for p in pats)


def report_at(lines, i):
    """The report whose header is on lines[i], and whether it is complete:
    followed by another report or a line that is not part of a report, or
    its "attempted at" stack has reached the syscall or kernel-thread entry
    frame that ends a WITNESS stack."""
    out = [lines[i].split(HEADER, 1)[1]]
    attempted = False
    for l in lines[i + 1:]:
        if HEADER in l:
            out.append(l.split(HEADER, 1)[0])
            return "\n".join(out), True
        if not REPORT_LINE.match(l):
            return "\n".join(out), True
        out.append(l)
        if l.startswith("lock order ") and l.rstrip().endswith("attempted at:"):
            attempted = True
        elif attempted and STACK_END.search(l):
            return "\n".join(out), True
    return "\n".join(out), False


def has_unknown_lor(log, known):
    """True when some reversal report in log matches no entry of known.  A
    report the log ends inside is judged on what it holds."""
    pats = load_known(known)
    with open(log, errors="replace") as f:
        lines = [l.rstrip("\r") for l in f.read().split("\n")]
    return any(not is_known(report_at(lines, i)[0], pats)
               for i, l in enumerate(lines) if HEADER in l)


class Watch:
    def __init__(self, fatal, pats, check_lor):
        self.fatal = re.compile(fatal)
        self.pats = pats
        self.check_lor = check_lor
        self.lines = []
        self.partial = b""
        self.open_reports = []      # indexes of header lines not yet classified

    def feed(self, data):
        """Add log bytes; return a problem description or None."""
        buf = self.partial + data
        parts = buf.split(b"\n")
        self.partial = parts.pop()
        first = len(self.lines)
        for p in parts:
            self.lines.append(p.rstrip(b"\r").decode("utf-8", "replace"))
        new = self.lines[first:]
        tail = self.partial.rstrip(b"\r").decode("utf-8", "replace")
        for l in new + [tail]:
            if self.fatal.search(l):
                return "fatal console line: " + l.strip()
        if not self.check_lor:
            return None
        for i in range(first, len(self.lines)):
            if HEADER in self.lines[i]:
                self.open_reports.append(i)
        return self.classify()

    def report(self, i):
        """The report starting at header line i, and whether it is complete
        (report_at); one the log has not finished yet stays open."""
        return report_at(self.lines, i)

    def classify(self):
        """Judge the open reports that are complete; keep the others open.
        Returns a problem description or None."""
        still = []
        problem = None
        for i in self.open_reports:
            block, done = self.report(i)
            if not done:
                still.append(i)
            elif not is_known(block, self.pats) and problem is None:
                problem = "lock order reversal matching no known-lor.txt entry"
        self.open_reports = still
        return problem


def stop(pid, kq, grace):
    """Wait up to grace seconds (0: only look) for pid's exit event, then
    SIGTERM it and wait for its exit.  The shell reaps QEMU as soon as it
    exits, after which its pid may name another process: never signal it
    once its exit event has arrived.  Returns True if it had exited by
    itself."""
    exited = wait_exit(kq, grace)
    if not exited:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            exited = True
        else:
            # The exit event has not been consumed yet: wait for it.
            wait_exit(kq, None)
            return False
    print("qemu had already exited", flush=True)
    return True


def wait_exit(kq, timeout):
    """Block until the EVFILT_PROC exit event, or for at most timeout
    seconds (None: no limit, 0: only look); True when it arrived."""
    deadline = None if timeout is None else time.monotonic() + timeout
    while True:
        left = None if deadline is None else max(0.0, deadline - time.monotonic())
        for ev in kq.control(None, 4, left):
            if ev.filter == select.KQ_FILTER_PROC:
                return True
        if deadline is not None and time.monotonic() >= deadline:
            return False


def monitor(args):
    pid, log, deadline = int(args["--pid"]), args["--log"], float(args["--deadline"])
    grace = float(args.get("--grace", FATAL_GRACE_S))
    w = Watch(args["--fatal"], load_known(args["--known"]),
              args.get("--fatal-lor", "yes") != "no")
    kq = select.kqueue()
    fd = os.open(log, os.O_RDONLY)
    kq.control([select.kevent(fd, select.KQ_FILTER_VNODE,
                              select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                              select.KQ_NOTE_WRITE | select.KQ_NOTE_EXTEND)], 0)
    try:
        kq.control([select.kevent(pid, select.KQ_FILTER_PROC,
                                  select.KQ_EV_ADD | select.KQ_EV_ONESHOT,
                                  select.KQ_NOTE_EXIT)], 0)
    except OSError as e:
        if e.errno != errno.ESRCH:
            raise
        # QEMU is gone before it could be watched (and may already be
        # reaped): never signal the pid; read what it wrote.
        while True:
            d = os.read(fd, 1 << 16)
            if not d:
                break
            p = w.feed(d)
            if p:
                print("KERNEL/INIT PROBLEM in serial log", flush=True)
                break
        print("qemu had exited before the monitor started", flush=True)
        return 5

    def drain():
        while True:
            d = os.read(fd, 1 << 16)
            if not d:
                return None
            p = w.feed(d)
            if p:
                return p

    problem = drain()
    while problem is None:
        left = deadline - time.time()
        if left <= 0:
            print("TIMEOUT", flush=True)
            stop(pid, kq, 0)
            return 4
        evs = kq.control(None, 4, left)
        exited = any(e.filter == select.KQ_FILTER_PROC for e in evs)
        problem = drain()
        if exited and problem is None:
            return 0
        if exited:
            # The guest is gone: the post-run checks of vm-provider.sh see
            # the whole log; report what was seen.
            print("KERNEL/INIT PROBLEM in serial log", flush=True)
            print("qemu had already exited", flush=True)
            return 3
    print("KERNEL/INIT PROBLEM in serial log", flush=True)
    stop(pid, kq, grace)
    return 3


def main(argv):
    if len(argv) == 4 and argv[1] == "--has-unknown-lor":
        try:
            return 0 if has_unknown_lor(argv[2], argv[3]) else 1
        except (OSError, ValueError, re.error) as e:
            print("vm-monitor: %s" % e, file=sys.stderr)
            return 2
    args, it = {}, iter(argv[1:])
    for a in it:
        args[a] = next(it, None)
    need = ("--pid", "--log", "--deadline", "--fatal", "--known")
    if any(args.get(k) is None for k in need):
        print("usage: vm-monitor.py --pid PID --log LOG --deadline EPOCH "
              "--fatal REGEX --known FILE [--fatal-lor yes|no] "
              "[--grace S]", file=sys.stderr)
        return 2
    try:
        return monitor(args)
    except (OSError, ValueError, re.error) as e:
        print("vm-monitor: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
