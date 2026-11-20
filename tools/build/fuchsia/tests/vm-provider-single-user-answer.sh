#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# vm-monitor.py --answer (vm-provider.sh SINGLE_USER_SHELL), with a stand-in
# QEMU: a Python program that serves the console socket, prints the
# single-user prompt (no newline) to the serial log and copies what it is
# sent to the log.  No guest.
# - The prompt is answered once, through the socket, with the text and a
#   newline, one byte per echo; the monitor prints CONSOLE_ANSWERED and the
#   run ends cleanly.
# - Unrelated console output between a typed byte and its echo (a kernel
#   message), and a prompt written in two parts, do not make the monitor send
#   the next byte early.  The stand-in checks that with a one-second absence
#   window after the unrelated line: proving that nothing was sent needs a
#   window; nothing waits on a condition with it.  The noiseless run also
#   checks the prompt in two parts: its second part contains "/", the first
#   byte typed.
# - A second prompt after the answer stops the run as a problem.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
mon=$root/vm-monitor.py
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fail() { echo "FAIL: $*"; exit 1; }
log=$work/serial.log sock=$work/console.sock
cat > "$work/fake.py" <<'EOS'
import os, select, socket, sys
log, sock, prompts = sys.argv[1], sys.argv[2], int(sys.argv[3])
noise = len(sys.argv) > 4
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sock); s.listen(1)
def out(t):
    with open(log, "a") as f:
        f.write(t)
early = 0
for i in range(prompts):
    # The prompt in two writes, as a console may deliver it.
    out("Enter full pathname of shell")
    out(" or RETURN for /bin/sh: ")
    c, _ = s.accept()
    got = b""
    while not got.endswith(b"\n"):
        d = c.recv(1)
        if not d:
            break
        got += d
        if noise and d != b"\n":
            # Unrelated console output before the echo; then, for an
            # absence window, check the next byte has not been sent yet.
            out("\nkernel: unrelated console line\n")
            r, _, _ = select.select([c], [], [], 1.0)
            if r and c.recv(1, socket.MSG_PEEK):
                early += 1
        out(d.decode())     # a tty echoes what it reads
    c.close()
    out("\ngot: " + got.decode().strip() + "\n")
out("early bytes: %d\n" % early)
out("Powering system off\n")
EOS
# run PROMPTS [noise]: start the stand-in, monitor it; sets mrc, out.
run() {
	: > "$log"
	rm -f "$sock"
	python3.12 -I "$work/fake.py" "$log" "$sock" "$@" & q=$!
	mrc=0
	out=$(python3.12 -I "$mon" --pid $q --log "$log" \
	    --deadline $(($(date +%s) + 600)) --fatal 'panic:' \
	    --known "$root/known-lor.txt" --grace 1 \
	    --answer 'Enter full pathname of shell' \
	    --answer-text '/root/single.sh' --console "$sock") || mrc=$?
	kill $q 2>/dev/null || :
	wait $q 2>/dev/null || :
}
run 1
[ $mrc = 0 ] || fail "answered once: exit $mrc ($out)"
echo "$out" | grep -qx CONSOLE_ANSWERED || fail "no CONSOLE_ANSWERED: $out"
grep -qx 'got: /root/single.sh' "$log" || fail "answer not received: $(cat "$log")"
# Unrelated output between a typed byte and its echo, and a prompt written
# in two parts, do not send the next byte early.
run 1 noise
[ $mrc = 0 ] || fail "noise: exit $mrc ($out)"
grep -qx 'got: /root/single.sh' "$log" || fail "noise: answer not received"
grep -qx 'early bytes: 0' "$log" || fail "noise: a byte was sent before the echo: $(grep 'early bytes' "$log")"
run 2
[ $mrc = 3 ] || fail "second prompt: exit $mrc ($out)"
echo "$out" | grep -qx 'KERNEL/INIT PROBLEM in serial log' || fail "second prompt: $out"
echo 'PASS the single-user prompt is answered once through the console socket; a second prompt stops the run'
