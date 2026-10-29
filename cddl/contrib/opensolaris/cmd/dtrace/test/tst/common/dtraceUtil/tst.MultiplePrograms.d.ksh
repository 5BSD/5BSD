#!/bin/ksh -p
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 5BSD contributors
#

#
# ASSERTION:
#	One dtrace(1) invocation accepts several programs (-s, -n, -P), enables
#	all of them before tracing starts, and every program's clauses fire:
#	a program enabled after another is not refused because tracing has
#	already begun.
#
# SECTION: dtrace Utility/Options
#
# The script is POSIX sh so it can also be run where ksh is not installed.
#

if [ $# != 1 ]; then
	echo expected one argument: '<'dtrace-path'>'
	exit 2
fi

dtrace=$1
tst=tst.MultiplePrograms.d.ksh
dir=$(mktemp -d -t multiprog) || exit 1
trap 'rm -rf "$dir"' EXIT

fail()
{
	echo "$tst: $*"
	echo "--- stdout"; cat "$dir/out"
	echo "--- stderr"; cat "$dir/err"
	exit 1
}

expect()
{
	grep -qx "$1" "$dir/out" || fail "missing output line '$1'"
}

# A script with a BEGIN clause, a real system call probe and an END clause.
cat > "$dir/a.d" <<'EOF'
BEGIN { printf("s-begin\n"); }
syscall::ioctl:entry /pid == $pid && !seen/ { seen = 1; printf("s-syscall\n"); }
END { printf("s-end\n"); }
EOF

cat > "$dir/b.d" <<'EOF'
BEGIN { printf("b-begin\n"); }
tick-1s { printf("b-tick\n"); exit(0); }
EOF

# Two programs: a script and a probe description ending the trace.
$dtrace -q -s "$dir/a.d" -n 'tick-1s { printf("n-tick\n"); exit(0); }' \
    > "$dir/out" 2> "$dir/err"
[ $? -eq 0 ] || fail "two programs (-s -n): dtrace failed"
for l in s-begin s-syscall n-tick s-end; do expect $l; done

# Three programs: -n, -s and -P (every dtrace provider probe, of which BEGIN
# and END fire).
$dtrace -q -n 'BEGIN { printf("n-begin\n"); }' -s "$dir/b.d" \
    -P 'dtrace { printf("P-%s\n", probename); }' > "$dir/out" 2> "$dir/err"
[ $? -eq 0 ] || fail "three programs (-n -s -P): dtrace failed"
for l in n-begin b-begin b-tick P-BEGIN P-END; do expect $l; done

# Programs are enabled in command-line order, so their BEGIN clauses fire in
# that order.
[ "$(grep -E '^(n|b|P)-BEGIN$|^(n|b)-begin$' "$dir/out" | tr '\n' ' ')" = \
    "n-begin b-begin P-BEGIN " ] || fail "BEGIN clauses out of program order"

# Two scripts and two descriptions, one of which matches nothing (-Z).
$dtrace -q -Z -s "$dir/a.d" -n 'nosuch:::probe { trace(1); }' \
    -s "$dir/b.d" -n 'END { printf("n-end\n"); }' > "$dir/out" 2> "$dir/err"
[ $? -eq 0 ] || fail "four programs with -Z: dtrace failed"
for l in s-begin s-syscall b-begin b-tick s-end n-end; do expect $l; done

exit 0
