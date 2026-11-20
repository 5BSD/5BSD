#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# Unit test of vm-monitor.py's console answer decisions, with fixed
# sequences and no processes or clocks: Typist (when the next byte may be
# typed) and Watch (when a prompt is whole).
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
python3.12 -I - "$root/vm-monitor.py" <<'EOS'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("vm_monitor", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
fails = []
def check(name, got, want):
    if got != want:
        fails.append("%s: got %r, want %r" % (name, got, want))

def typist_after(chunks, pending=b"/r", sent=b"r"):
    t = m.Typist(pending)
    assert t.next() == pending[:1]
    if pending[1:2] == sent:
        t.output(pending[:1])           # the first byte's echo
        t.next()
    for c in chunks:
        t.output(c)
    return t.ready()

# Before anything is typed the first byte may go.
check("nothing typed", m.Typist(b"/r").ready(), True)
# The plain echo.
check("echo", typist_after([b"r"]), True)
# Nothing yet.
check("no output", typist_after([]), False)
# Noise with no echo: whole lines, one containing the pending byte.
check("noise, no echo",
      typist_after([b"\nkernel: unrelated console line\n"]), False)
check("noise in two reads, no echo",
      typist_after([b"\nkernel: unrel", b"ated line\n"]), False)
# The echo after noise: it starts the line begun after the message.
check("echo after noise",
      typist_after([b"\nkernel: unrelated console line\n", b"r"]), True)
# The echo, then noise, in one read.
check("echo then noise in one read",
      typist_after([b"r\nkernel: unrelated console line\n"]), True)
# A partial-line printf around the echo, with and without its newline.
check("printf around the echo", typist_after([b"kern", b"r", b"el: x"]), True)
check("printf around the echo, then newline",
      typist_after([b"kern" + b"r" + b"el: x\n"]), True)
# The echo after noise, followed by more output on its line.
check("echo after noise, printf after it",
      typist_after([b"\nkernel: a\nr", b"kernel: b"]), True)
# CR LF line ends.
check("CR LF noise, no echo", typist_after([b"\r\nkernel: x\r\n"]), False)
# The answer ends with a newline, and nothing waits for its echo.
t = m.Typist(b"ab")
seq = [t.next()]
t.output(b"a"); seq.append(t.next())
t.output(b"b"); seq.append(t.next())
check("sequence", seq, [b"a", b"b", b"\n"])
check("done after the newline", t.done(), True)
# Only printable ASCII.
for bad in (b"", b"a\x01", b"a\n", b"\x7f", "é".encode()):
    try:
        m.Typist(bad)
        fails.append("accepted %r" % bad)
    except ValueError:
        pass

# A prompt written in two parts is a prompt only once whole; one prompt
# line counts once however it is fed; a second prompt counts again.
w = m.Watch("x^", [], False, "Enter full pathname of shell.*: $")
w.feed(b"Enter full pathname of shell")
check("half a prompt", w.want_answer, False)
w.feed(b" or RETURN for /bin/sh: ")
check("whole prompt", w.want_answer, True)
w.want_answer = False
w.answered = 1
check("echo on the prompt line", w.feed(b"/root/x"), None)
check("answer line ends", w.feed(b"\nmore output\n"), None)
check("second prompt",
      w.feed(b"Enter full pathname of shell or RETURN for /bin/sh: "),
      "console prompt again after it was answered")

if fails:
    print("FAIL: " + "; ".join(fails))
    sys.exit(1)
print("PASS Typist types on the echo despite surrounding output, refuses non-printable answers; Watch answers whole prompts once")
EOS
