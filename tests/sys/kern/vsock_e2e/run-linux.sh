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
# TRANSPORT (modern or default legacy), HOST_WORK, and optional BHYVE_LOG,
# CONSOLE_LOG_PATH, and SMOKE_ONLY diagnostics/lifecycle controls.
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
SMOKE_ONLY=${SMOKE_ONLY:-no}
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
gwait() {
	_pattern=$1
	$ACMD "i=0; while ! grep -Eq '$_pattern' /tmp/g.out 2>/dev/null && \
	    [ \"\$i\" -lt 10 ]; do sleep 1; i=\$((i + 1)); done; \
	    grep -Eq '$_pattern' /tmp/g.out" 15 >/dev/null
}

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
case "$SMOKE_ONLY" in
yes|no) ;;
*) echo "SMOKE_ONLY must be yes or no" >&2; exit 2 ;;
esac

# Fail before the data tests unless the exact expected PCI function is uniquely
# bound to the upstream driver.  The helper also proves AF_VSOCK socket
# creation, so a similarly named but unbound device cannot satisfy preflight.
$ACMD "test -r $GPY && python3 $GPY preflight $TRANSPORT" 20 >/dev/null || {
	echo "Alpine preflight failed: helper, driver binding, or PCI identity" >&2
	dump_context
	exit 2
}

# Lock down guest-initiated behavior for the reserved hypervisor CID and the
# host CID with no listener.  CID 0 is unreachable and times out on Linux;
# CID 2 is routable, so bhyve must answer the unused port with RST.
if reserved_out=$($ACMD "python3 $GPY reserved-cids" 12); then
	reserved_rc=0
else
	reserved_rc=$?
fi
if [ "$reserved_rc" -ne 0 ] ||
    [ "$reserved_out" != "PASS reserved-cids cid0=ETIMEDOUT cid2=ECONNRESET" ]; then
	diag_capture reserved_cids "$reserved_rc" "$reserved_out"
	dump_context
	exit 2
fi
echo "PASS  preflight_reserved_cids"

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

if [ "$SMOKE_ONLY" = yes ]; then
	echo "----"
	echo "linux e2e smoke: 2 passed, 0 failed"
	exit 0
fi

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

# Require a host write-half shutdown to reach the guest as EOF.  The guest
# then closes its endpoint, which must return EOF to vsh-connect as well.
close_token=E2E-H2G-SEQ-CLOSE
gbg "close-l seq 7010 $close_token"
if out=$(printf %s "$close_token" |
    vshc "$DIR" 7010 -s); then
	rc=0
else
	rc=$?
fi
sleep 1
if o=$(gout); then guest_rc=0; else guest_rc=$?; fi
printf '%s\n' "$o" | grep -q '^PASS graceful-close-listener type=seq$' &&
    [ "$rc" -eq 0 ] && [ "$guest_rc" -eq 0 ] && [ -z "$out" ]
ok=$?
if [ "$ok" -ne 0 ]; then
	diag_capture seqpacket_graceful_close_h2g "$rc" "$o"
	echo "  guest status=$guest_rc host-bytes=$(printf %s "$out" | wc -c | tr -d ' ')" >&2
fi
res seqpacket_graceful_close_h2g "$ok"

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

# The guest now initiates the write-half shutdown.  unix-pipe must drain the
# record and observe EOF before closing, and the guest must observe that close
# as EOF rather than timing out or being reset.
close_token=E2E-G2H-SEQ-CLOSE
rm -f "$DIR/7011"
timeout 20 "$TOOLS/unix-pipe" -l -s -d "$DIR/7011" \
    >"$HOST_WORK/7011.close.out" 2>"$HOST_WORK/7011.listener.log" &
lpid=$!
sleep 1
if o=$($ACMD "python3 $GPY close seq 7011 $close_token" 15); then
	guest_rc=0
else
	guest_rc=$?
fi
listener_rc=0; wait "$lpid" 2>/dev/null || listener_rc=$?
if close_out=$(cat "$HOST_WORK/7011.close.out"); then host_read_rc=0; else host_read_rc=$?; fi
[ "$guest_rc" -eq 0 ] && [ "$listener_rc" -eq 0 ] &&
    [ "$host_read_rc" -eq 0 ] && [ "$close_out" = "$close_token" ] &&
    [ "$o" = 'PASS graceful-close-client type=seq' ]
ok=$?
if [ "$ok" -ne 0 ]; then
	diag_capture seqpacket_graceful_close_g2h "$guest_rc" "$o"
	echo "  listener status=$listener_rc read-status=$host_read_rc" >&2
	diag_capture seqpacket_graceful_close_g2h_payload "$host_read_rc" "$close_out"
	cat "$HOST_WORK/7011.listener.log" >&2 || true
fi
res seqpacket_graceful_close_g2h "$ok"

# Kill the established host endpoint without shutdown/close cooperation.  The
# guest must observe EOF or reset promptly, and a fresh connection afterward
# proves the device remains usable.
gbg "abrupt-l stream 7012"
abrupt_log="$HOST_WORK/7012.abrupt.log"
"$TOOLS/vsh-connect" -w "$DIR" 7012 >"$abrupt_log" 2>&1 &
abrupt_pid=$!
abrupt_ready=no
i=0
while [ "$i" -lt 10 ]; do
	if grep -q '^READY$' "$abrupt_log" 2>/dev/null; then
		abrupt_ready=yes
		break
	fi
	if ! kill -0 "$abrupt_pid" 2>/dev/null; then
		break
	fi
	sleep 1
	i=$((i + 1))
done
abrupt_kill_rc=1
abrupt_wait_rc=0
if [ "$abrupt_ready" = yes ]; then
	if kill -KILL "$abrupt_pid" 2>/dev/null; then abrupt_kill_rc=0; fi
fi
wait "$abrupt_pid" 2>/dev/null || abrupt_wait_rc=$?
guest_wait_rc=0
gwait '^PASS abrupt-disconnect-listener outcome=(EOF|ECONNRESET|ENOTCONN)$' ||
    guest_wait_rc=$?
if o=$(gout); then guest_rc=0; else guest_rc=$?; fi
printf '%s\n' "$o" |
    grep -Eq '^PASS abrupt-disconnect-listener outcome=(EOF|ECONNRESET|ENOTCONN)$' &&
    [ "$abrupt_ready" = yes ] && [ "$abrupt_kill_rc" -eq 0 ] &&
    [ "$abrupt_wait_rc" -ne 0 ] && [ "$guest_wait_rc" -eq 0 ] &&
    [ "$guest_rc" -eq 0 ]
ok=$?
if [ "$ok" -ne 0 ]; then
	diag_capture abrupt_host_kill_guest_observe "$guest_rc" "$o"
	echo "  ready=$abrupt_ready kill=$abrupt_kill_rc wait=$abrupt_wait_rc guest-wait=$guest_wait_rc" >&2
	cat "$abrupt_log" >&2 || true
fi
res abrupt_host_kill_guest_observe "$ok"

gbg "echo-l stream 7013"
if out=$(printf 'E2E-AFTER-HOST-KILL' |
    vshc "$DIR" 7013); then
	rc=0
else
	rc=$?
fi
[ "$rc" -eq 0 ] && [ "$out" = "E2E-AFTER-HOST-KILL" ]
ok=$?
[ "$ok" -eq 0 ] || diag_capture after_abrupt_host_kill "$rc" "$out"
res after_abrupt_host_kill "$ok"

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
