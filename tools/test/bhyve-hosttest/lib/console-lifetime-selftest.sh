#!/bin/sh
# No VM or root: exercise console detach, signals and partial evidence.
set -eu
helper=${1:-$(dirname "$0")/acmd-console.sh}
t=$(mktemp -d /tmp/console-lifetime.XXXXXX)
pid=
trap '[ -z "$pid" ] || kill "$pid" 2>/dev/null || :; rm -rf "$t"' EXIT
fail=0
check() { if "$@"; then :; else echo "FAIL $*"; fail=1; fi; }
start()
{
	: > "$t/log"; : > "$t/input"; : > "$t/alive"
	CONSOLE_LOG=$t/log CONSOLE_INPUT=$t/input CONSOLE_LIFETIME=$t/alive \
	    sh "$helper" "$1" 5 > "$t/out" 2> "$t/err" &
	pid=$!
	i=0
	while [ ! -s "$t/input" ] && [ "$i" -lt 100 ]; do sleep 0.02; i=$((i + 1)); done
	[ -s "$t/input" ]
}
finish()
{
	if wait "$pid"; then rc=0; else rc=$?; fi
	pid=
}
start 'echo hello'
b=$(sed -n 's/.*\(__VSOCK_BEGIN_[0-9_]*__\).*/\1/p' "$t/input")
printf '%s\r\npartial-before-detach\r\n' "$b" >> "$t/log"
rm "$t/alive"
finish
check test "$rc" -eq 125
check grep -qx partial-before-detach "$t/out"
check grep -q 'console detached' "$t/err"
# A missing lifetime must reject a command without writing to the input.
: > "$t/input"
if CONSOLE_LOG=$t/log CONSOLE_INPUT=$t/input CONSOLE_LIFETIME=$t/alive \
    sh "$helper" : 1 > "$t/out" 2> "$t/err"; then rc=0; else rc=$?; fi
check test "$rc" -eq 125
check test ! -s "$t/input"
# Cancellation must also interrupt acknowledgement waits for long commands.
long=$(jot -b x 500 | tr -d '\n')
start "$long"
rm "$t/alive"
finish
check test "$rc" -eq 125
check grep -q 'console detached' "$t/err"
# TERM is what explicit cleanup can send to a background command. POSIX
# asynchronous shells may inherit ignored SIGINT, so do not rely on it.
start 'echo hello'
b=$(sed -n 's/.*\(__VSOCK_BEGIN_[0-9_]*__\).*/\1/p' "$t/input")
printf '%s\r\npartial-before-term\r\n' "$b" >> "$t/log"
kill -TERM "$pid"
finish
check test "$rc" -eq 143
check grep -qx partial-before-term "$t/out"
[ "$fail" -eq 0 ] && echo 'PASS console cancellation and interrupted evidence'
exit "$fail"
