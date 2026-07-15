#!/bin/sh
# vsock end-to-end driver for a LINUX guest (companion to run.sh, which drives a
# 5BSD guest).  The FreeBSD guest tools (vsock-pipe) do not build on Linux, so
# the guest side is driven by gvsock.py (AF_VSOCK via python3, shipped here);
# the HOST side reuses the same unix-pipe / vsh-connect binaries as run.sh.
#
# Covers the same matrix for BOTH socket types and BOTH directions:
#   echo (stream/seqpacket, h2g/g2h), a large record delivered whole
#   (seqpacket, h2g/g2h), and a bulk transfer (stream, h2g/g2h).
#
# Requirements:
#   - a running Linux guest (CID 3+) with the vsock device at path=$DIR, its
#     virtio-vsock modules loaded, and python3 present
#   - gvsock.py copied into the guest (e.g. /tmp/gvsock.py)
#   - $ACMD: runs its 1st arg in the guest and prints stdout (a console helper)
#   - $TOOLS names the object directory containing unix-pipe and vsh-connect
#
# Env: DIR, TOOLS, ACMD, GPY (guest path to gvsock.py), REC (record size bytes),
# TRANSPORT (modern or default legacy), HOST_WORK, and optional BHYVE_LOG and
# CONSOLE_LOG_PATH diagnostics.
set -u

DIR=${DIR:-$HOME/vm/vsock-sockdir-linux}
TOOLS=${TOOLS:-$(cd "$(dirname "$0")" && pwd)}
ACMD=${ACMD:-"sh $HOME/vm/acmd.sh"}
GPY=${GPY:-/tmp/gvsock.py}
REC=${REC:-204800}
TRANSPORT=${TRANSPORT:-modern}
HOST_WORK=${HOST_WORK:-${TMPDIR:-/tmp}/vsock-linux-e2e.$$}
BHYVE_LOG=${BHYVE_LOG:-}
CONSOLE_LOG_PATH=${CONSOLE_LOG_PATH:-}
mkdir -p "$HOST_WORK"

PASS=0; FAIL=0; FAILED=""
res() {
	if [ "$2" -eq 0 ]; then echo "PASS  $1"; PASS=$((PASS + 1))
	else echo "FAIL  $1"; FAIL=$((FAIL + 1)); FAILED="$FAILED $1"; fi
}
diag_capture() {
	label=$1
	rc=$2
	value=$3
	bytes=$(printf %s "$value" | wc -c | tr -d ' ')
	echo "  $label: rc=$rc bytes=$bytes" >&2
	printf %s "$value" | od -An -tx1 >&2
}
dump_context() {
	echo "---- vsock failure context ----" >&2
	echo "guest helper output:" >&2
	$ACMD 'cat /tmp/g.out 2>/dev/null || true' 12 >&2 || true
	echo "host socket directory:" >&2
	ls -la "$DIR" >&2 || true
	if [ -n "$BHYVE_LOG" ] && [ -r "$BHYVE_LOG" ]; then
		echo "recent bhyve log:" >&2
		tail -n 80 "$BHYVE_LOG" >&2 || true
	fi
	if [ -n "$CONSOLE_LOG_PATH" ] && [ -r "$CONSOLE_LOG_PATH" ]; then
		echo "recent guest console log:" >&2
		tail -n 40 "$CONSOLE_LOG_PATH" >&2 || true
	fi
	echo "---- end failure context ----" >&2
}
# Start a backgrounded guest helper (server), wait for its "up" line.
gbg() {
	if ! $ACMD "pkill -9 python3 2>/dev/null; rm -f /tmp/g.out; \
	nohup python3 $GPY $1 >/tmp/g.out 2>&1 & \
	i=0; while ! grep -q '^up$' /tmp/g.out 2>/dev/null && [ \"\$i\" -lt 10 ]; \
	do sleep 1; i=\$((i + 1)); done; grep -q '^up$' /tmp/g.out" 15 >/dev/null; then
		echo "guest vsock helper failed to become ready: $1" >&2
		$ACMD 'cat /tmp/g.out 2>/dev/null || true' 12 >&2 || true
		dump_context
		exit 2
	fi
}
gout() { $ACMD 'cat /tmp/g.out; pkill -9 python3 2>/dev/null || true' 12; }

# A listener can report ready immediately before its REQUEST/RESPONSE reaches
# the host control path.  Retry only the device's explicit ECONNREFUSED status;
# every other connector error is returned immediately.
vshc() {
	_dir=$1
	_port=$2
	shift 2
	_try=0
	while [ "$_try" -lt 5 ]; do
		timeout 20 "$TOOLS/vsh-connect" "$@" "$_dir" "$_port"
		_rc=$?
		[ "$_rc" -ne 4 ] && return "$_rc"
		sleep 1
		_try=$((_try + 1))
	done
	return 4
}

echo "vsock linux e2e: DIR=$DIR REC=$REC"

case "$TRANSPORT" in
modern|legacy) ;;
*) echo "TRANSPORT must be modern or legacy" >&2; exit 2 ;;
esac

# Fail before the data tests unless the exact expected PCI function is uniquely
# bound to the upstream driver.  The helper also proves AF_VSOCK socket
# creation, so a similarly named but unbound device cannot satisfy preflight.
$ACMD "test -r $GPY && python3 $GPY preflight $TRANSPORT" 20 >/dev/null || {
	echo "Alpine preflight failed: helper, driver binding, or PCI identity" >&2
	dump_context
	exit 2
}

# Prove both directions before running the larger matrix.  Every subsequent
# case depends on these same control and data paths; cascading failures after
# either smoke probe only obscure the root cause.
gbg "echo-l stream 6991"
if smoke_out=$(printf 'VSOCK-SMOKE-H2G' |
    vshc "$DIR" 6991); then
	smoke_rc=0
else
	smoke_rc=$?
fi
if [ "$smoke_rc" -ne 0 ] || [ "$smoke_out" != VSOCK-SMOKE-H2G ]; then
	diag_capture smoke_h2g "$smoke_rc" "$smoke_out"
	dump_context
	exit 2
fi
echo "PASS  preflight_data_h2g"

rm -f "$DIR/6992"
timeout 20 "$TOOLS/unix-pipe" -l -e -n 1 "$DIR/6992" \
    >"$HOST_WORK/smoke-g2h.host.log" 2>&1 &
smoke_pid=$!
sleep 1
smoke_host_rc=0
if smoke_out=$($ACMD \
    "python3 $GPY send-echo stream 6992 VSOCK-SMOKE-G2H" 15); then
	smoke_rc=0
else
	smoke_rc=$?
fi
wait "$smoke_pid" 2>/dev/null || smoke_host_rc=$?
if [ "$smoke_rc" -ne 0 ] || [ "$smoke_host_rc" -ne 0 ] ||
    [ "$smoke_out" != "ECHO VSOCK-SMOKE-G2H" ]; then
	diag_capture smoke_g2h "$smoke_rc" "$smoke_out"
	echo "  host listener rc=$smoke_host_rc" >&2
	cat "$HOST_WORK/smoke-g2h.host.log" >&2 || true
	dump_context
	exit 2
fi
echo "PASS  preflight_data_g2h"

# --- host->guest (guest is the server) ---
gbg "echo-l stream 7001"
if out=$(printf 'E2E-H2G-STREAM' |
    vshc "$DIR" 7001); then
	rc=0
else
	rc=$?
fi
[ "$rc" -eq 0 ] && [ "$out" = "E2E-H2G-STREAM" ]
ok=$?
[ "$ok" -eq 0 ] || diag_capture stream_echo_h2g "$rc" "$out"
res stream_echo_h2g "$ok"

gbg "echo-l seq 7002"
if out=$(printf 'E2E-H2G-SEQ' |
    vshc "$DIR" 7002 -s); then
	rc=0
else
	rc=$?
fi
[ "$rc" -eq 0 ] && [ "$out" = "E2E-H2G-SEQ" ]
ok=$?
[ "$ok" -eq 0 ] || diag_capture seqpacket_echo_h2g "$rc" "$out"
res seqpacket_echo_h2g "$ok"

gbg "recv-l seq 7003"
if head -c "$REC" /dev/zero | tr '\0' A |
    vshc "$DIR" 7003 -s -1 >/dev/null; then rc=0; else rc=$?; fi
sleep 1
if o=$(gout); then guest_rc=0; else guest_rc=$?; fi
printf '%s\n' "$o" | grep -q "RECORD len=$REC" &&
    [ "$(printf '%s\n' "$o" | grep -c '^RECORD')" = 1 ] &&
    [ "$rc" -eq 0 ] && [ "$guest_rc" -eq 0 ]
ok=$?
if [ "$ok" -ne 0 ]; then
	diag_capture seqpacket_bigrecord_h2g "$rc" "$o"
	echo "  guest status=$guest_rc" >&2
fi
res seqpacket_bigrecord_h2g "$ok"

gbg "recv-l stream 7004"
if head -c "$REC" /dev/zero | tr '\0' B |
    vshc "$DIR" 7004 -1 >/dev/null; then rc=0; else rc=$?; fi
sleep 1
if o=$(gout); then guest_rc=0; else guest_rc=$?; fi
printf '%s\n' "$o" | grep -q "bytes=$REC" &&
    [ "$rc" -eq 0 ] && [ "$guest_rc" -eq 0 ]
ok=$?
if [ "$ok" -ne 0 ]; then
	diag_capture stream_bulk_h2g "$rc" "$o"
	echo "  guest status=$guest_rc" >&2
fi
res stream_bulk_h2g "$ok"

# --- guest->host (host is the server) ---
rm -f "$DIR/7005"; timeout 20 "$TOOLS/unix-pipe" -l -e -n 1 "$DIR/7005" \
    >"$HOST_WORK/7005.listener.log" 2>&1 &
lpid=$!
sleep 1
if o=$($ACMD "python3 $GPY send-echo stream 7005 E2E-G2H-STREAM" 15); then
	guest_rc=0
else
	guest_rc=$?
fi
listener_rc=0; wait "$lpid" 2>/dev/null || listener_rc=$?
[ "$guest_rc" -eq 0 ] && [ "$listener_rc" -eq 0 ] &&
    [ "$o" = 'ECHO E2E-G2H-STREAM' ]
ok=$?
if [ "$ok" -ne 0 ]; then
	diag_capture stream_echo_g2h "$guest_rc" "$o"
	echo "  listener status=$listener_rc" >&2
	cat "$HOST_WORK/7005.listener.log" >&2 || true
fi
res stream_echo_g2h "$ok"

rm -f "$DIR/7006"; timeout 20 "$TOOLS/unix-pipe" -l -s -e -n 1 "$DIR/7006" \
    >"$HOST_WORK/7006.listener.log" 2>&1 &
lpid=$!
sleep 1
if o=$($ACMD "python3 $GPY send-echo seq 7006 E2E-G2H-SEQ" 15); then
	guest_rc=0
else
	guest_rc=$?
fi
listener_rc=0; wait "$lpid" 2>/dev/null || listener_rc=$?
[ "$guest_rc" -eq 0 ] && [ "$listener_rc" -eq 0 ] &&
    [ "$o" = 'ECHO E2E-G2H-SEQ' ]
ok=$?
if [ "$ok" -ne 0 ]; then
	diag_capture seqpacket_echo_g2h "$guest_rc" "$o"
	echo "  listener status=$listener_rc" >&2
	cat "$HOST_WORK/7006.listener.log" >&2 || true
fi
res seqpacket_echo_g2h "$ok"

rm -f "$DIR/7007"; timeout 30 "$TOOLS/unix-pipe" -l -s -d "$DIR/7007" \
    > "$HOST_WORK/g2h.seq.out" 2>"$HOST_WORK/7007.listener.log" &
lpid=$!
sleep 1
if $ACMD "python3 $GPY send seq 7007 $REC" 20 >/dev/null; then
	guest_rc=0
else
	guest_rc=$?
fi
listener_rc=0; wait "$lpid" 2>/dev/null || listener_rc=$?
got=$(wc -c < "$HOST_WORK/g2h.seq.out" | tr -d ' ')
[ "$guest_rc" -eq 0 ] && [ "$listener_rc" -eq 0 ] && [ "$got" = "$REC" ]
ok=$?
if [ "$ok" -ne 0 ]; then
	echo "  seqpacket_bigrecord_g2h: guest=$guest_rc listener=$listener_rc bytes=$got expected=$REC" >&2
	cat "$HOST_WORK/7007.listener.log" >&2 || true
fi
res seqpacket_bigrecord_g2h "$ok"

rm -f "$DIR/7008"; timeout 30 "$TOOLS/unix-pipe" -l -d "$DIR/7008" \
    > "$HOST_WORK/g2h.stream.out" 2>"$HOST_WORK/7008.listener.log" &
lpid=$!
sleep 1
if $ACMD "python3 $GPY send stream 7008 $REC" 20 >/dev/null; then
	guest_rc=0
else
	guest_rc=$?
fi
listener_rc=0; wait "$lpid" 2>/dev/null || listener_rc=$?
got=$(wc -c < "$HOST_WORK/g2h.stream.out" | tr -d ' ')
[ "$guest_rc" -eq 0 ] && [ "$listener_rc" -eq 0 ] && [ "$got" = "$REC" ]
ok=$?
if [ "$ok" -ne 0 ]; then
	echo "  stream_bulk_g2h: guest=$guest_rc listener=$listener_rc bytes=$got expected=$REC" >&2
	cat "$HOST_WORK/7008.listener.log" >&2 || true
fi
res stream_bulk_g2h "$ok"

echo "----"
echo "linux e2e: $PASS passed, $FAIL failed$( [ -n "$FAILED" ] && echo " ($FAILED )" )"
[ "$FAIL" -eq 0 ] || dump_context
[ "$FAIL" -eq 0 ]
