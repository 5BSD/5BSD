#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# vm-monitor.py --answer (vm-provider.sh SINGLE_USER_SHELL) end to end, with
# a stand-in QEMU: a Python program that serves the console socket, prints
# the single-user prompt in two writes (no newline) to the serial log,
# echoes what it reads like a tty, with an unrelated console line before
# each echo, and copies the whole answer to the log.  No guest.  The echo
# decisions themselves are unit-tested in vm-monitor-typist.sh.
# - The prompt is answered once, after it is whole, through the socket; the
#   answer gets through and the monitor prints CONSOLE_ANSWERED.
# - A second prompt after the answer stops the run as a problem.
# - An answer that is not printable ASCII is refused before anything runs.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
mon=$root/vm-monitor.py
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fail() { echo "FAIL: $*"; exit 1; }
log=$work/serial.log sock=$work/console.sock
cat > "$work/fake.py" <<'EOS'
import socket, sys
log, sock, prompts = sys.argv[1], sys.argv[2], int(sys.argv[3])
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sock); s.listen(1)
def out(t):
    with open(log, "a") as f:
        f.write(t)
for i in range(prompts):
    out("Enter full pathname of shell")
    out(" or RETURN for /bin/sh: ")
    c, _ = s.accept()
    got = b""
    while not got.endswith(b"\n"):
        d = c.recv(1)
        if not d:
            break
        got += d
        if d != b"\n":
            out("\nkernel: unrelated console line\n")
        out(d.decode())
    c.close()
    out("\ngot: " + got.decode().strip() + "\n")
out("Powering system off\n")
EOS
# run PROMPTS [TEXT]: start the stand-in, monitor it; sets mrc, out.
run() {
	: > "$log"
	rm -f "$sock"
	python3.12 -I "$work/fake.py" "$log" "$sock" "$1" & q=$!
	mrc=0
	out=$(python3.12 -I "$mon" --pid $q --log "$log" \
	    --deadline $(($(date +%s) + 600)) --fatal 'panic:' \
	    --known "$root/known-lor.txt" --grace 1 \
	    --answer 'Enter full pathname of shell.*: $' \
	    --answer-text "${2:-/root/single.sh}" --console "$sock" 2>&1) || mrc=$?
	kill $q 2>/dev/null || :
	wait $q 2>/dev/null || :
}
run 1
[ $mrc = 0 ] || fail "answered once: exit $mrc ($out)"
echo "$out" | grep -qx CONSOLE_ANSWERED || fail "no CONSOLE_ANSWERED: $out"
grep -qx 'got: /root/single.sh' "$log" || fail "answer not received: $(cat "$log")"
run 2
[ $mrc = 3 ] || fail "second prompt: exit $mrc ($out)"
echo "$out" | grep -qx 'KERNEL/INIT PROBLEM in serial log' || fail "second prompt: $out"
run 1 "$(printf '/root/x\001')"
[ $mrc = 2 ] || fail "control character: exit $mrc ($out)"
echo 'PASS the single-user prompt is answered once, when whole, through the console socket; a second prompt stops the run; a control character is refused'
