#!/bin/sh
# vsock end-to-end driver for a LINUX guest (companion to run.sh, which drives a
# 5BSD guest).  The FreeBSD guest tools (vsock-pipe) do not build on Linux, so
# the guest side is driven by gvsock.py (AF_VSOCK via python3, shipped here);
# the host side uses unix-pipe/vsh-connect for backend=userspace and vsock-pipe
# over the host AF_VSOCK domain for backend=kernel.
#
# Covers the same matrix for BOTH socket types and BOTH directions:
#   echo (stream/seqpacket, h2g/g2h), a large record delivered whole
#   (seqpacket, h2g/g2h), and a bulk transfer (stream, h2g/g2h).
#
# Requirements:
#   - a running Linux guest (CID 3+) with a virtio-vsock device, its modules
#     loaded, and python3 present; backend=userspace also requires path=$DIR
#   - gvsock.py copied into the guest (e.g. /tmp/gvsock.py)
#   - $ACMD: runs its 1st arg in the guest and prints stdout (a console helper)
#   - $TOOLS names the object directory containing unix-pipe, vsh-connect,
#     and vsock-pipe
#
# Env: DIR, TOOLS, ACMD, GPY (guest path to gvsock.py), REC (record size bytes),
# TRANSPORT (modern or default legacy), BACKEND (userspace or kernel), GUEST_CID
# (required and checked against the guest transport), HOST_WORK, PORT_OFFSET
# (added to every test port for concurrent VMs), and optional BHYVE_LOG,
# CONSOLE_LOG_PATH,
# and MODE diagnostics/lifecycle controls.  MODE is one of full, smoke, or
# churn.  The churn mode intentionally skips the full conformance preflight
# and runs 4 * CHURN_CONNECTIONS concurrent data/close lifecycles; callers
# must bracket it with full validation.
set -u

DIR=${DIR:-$HOME/vm/vsock-sockdir-linux}
TOOLS=${TOOLS:-$(cd "$(dirname "$0")" && pwd)}
ACMD=${ACMD:-"sh $HOME/vm/acmd.sh"}
GPY=${GPY:-/tmp/gvsock.py}
REC=${REC:-204800}
TRANSPORT=${TRANSPORT:-modern}
BACKEND=${BACKEND:-userspace}
GUEST_CID=${GUEST_CID:-}
HOST_WORK=${HOST_WORK:-${TMPDIR:-/tmp}/vsock-linux-e2e.$$}
BHYVE_LOG=${BHYVE_LOG:-}
CONSOLE_LOG_PATH=${CONSOLE_LOG_PATH:-}
MODE=${MODE:-full}
CHURN_CONNECTIONS=${CHURN_CONNECTIONS:-8}
PORT_OFFSET=${PORT_OFFSET:-0}
VSOCK_PACKED=${VSOCK_PACKED:-no}
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
	if [ "$BACKEND" = userspace ]; then
		echo "host socket directory:" >&2
		ls -la "$DIR" >&2 || true
	else
		echo "host backend: kernel guest_cid=$GUEST_CID" >&2
	fi
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

run_parallel_h2g() {
	ph_type=$1
	ph_base=$2
	ph_count=$3
	ph_flags=
	[ "$ph_type" = stream ] || ph_flags=-s
	ph_dir="$HOST_WORK/parallel-h2g-$ph_type"
	mkdir -p "$ph_dir"
	# HOST_WORK is intentionally reusable for post-failure diagnosis.  Remove
	# only this case's prior result files so a worker killed before writing its
	# status cannot be mistaken for a successful worker from an earlier run.
	rm -f "$ph_dir"/*.out "$ph_dir"/*.err "$ph_dir"/*.status
	gbg "parallel-echo-l $ph_type $ph_base $ph_count"
	ph_pids=
	ph_i=0
	while [ "$ph_i" -lt "$ph_count" ]; do
		ph_port=$((ph_base + ph_i))
		ph_token=$(printf 'PARALLEL-%s-%02d' "$ph_type" "$ph_i")
		(
			printf %s "$ph_token" |
			    vshc "$DIR" "$ph_port" $ph_flags \
			    >"$ph_dir/$ph_i.out" 2>"$ph_dir/$ph_i.err"
			printf '%s\n' "$?" >"$ph_dir/$ph_i.status"
		) &
		ph_pids="$ph_pids $!"
		ph_i=$((ph_i + 1))
	done
	for ph_pid in $ph_pids; do
		wait "$ph_pid" 2>/dev/null || true
	done
	ph_ok=0
	ph_i=0
	while [ "$ph_i" -lt "$ph_count" ]; do
		ph_token=$(printf 'PARALLEL-%s-%02d' "$ph_type" "$ph_i")
		if [ ! -r "$ph_dir/$ph_i.status" ] ||
		    [ "$(cat "$ph_dir/$ph_i.status")" -ne 0 ] ||
		    [ "$(cat "$ph_dir/$ph_i.out")" != "$ph_token" ]; then
			ph_ok=1
		fi
		ph_i=$((ph_i + 1))
	done
	gwait "^PASS parallel-echo-listeners type=$ph_type count=$ph_count$" ||
	    ph_ok=1
	if ph_guest_out=$(gout); then
		ph_guest_rc=0
	else
		ph_guest_rc=$?
		ph_ok=1
	fi
	printf '%s\n' "$ph_guest_out" |
	    grep -q "^PASS parallel-echo-listeners type=$ph_type count=$ph_count$" ||
	    ph_ok=1
	if [ "$ph_ok" -ne 0 ]; then
		diag_capture "parallel_${ph_type}_h2g_guest" "$ph_guest_rc" \
		    "$ph_guest_out"
		ph_i=0
		while [ "$ph_i" -lt "$ph_count" ]; do
			echo "  client $ph_i status=$(cat "$ph_dir/$ph_i.status" 2>/dev/null || echo missing)" >&2
			cat "$ph_dir/$ph_i.err" >&2 2>/dev/null || true
			ph_i=$((ph_i + 1))
		done
	fi
	res "parallel_${ph_type}_h2g" "$ph_ok"
}

run_parallel_g2h() {
	pg_type=$1
	pg_base=$2
	pg_count=$3
	pg_flags=
	[ "$pg_type" = stream ] || pg_flags=-s
	pg_dir="$HOST_WORK/parallel-g2h-$pg_type"
	mkdir -p "$pg_dir"
	rm -f "$pg_dir"/*.log
	pg_pids=
	pg_i=0
	while [ "$pg_i" -lt "$pg_count" ]; do
		pg_port=$((pg_base + pg_i))
		host_listener 30 "$pg_port" $pg_flags -e -n 1 \
		    >"$pg_dir/$pg_i.log" 2>&1 &
		pg_pids="$pg_pids $!"
		pg_i=$((pg_i + 1))
	done
	sleep 1
	if pg_guest_out=$($ACMD \
	    "python3 $GPY parallel-send-echo $pg_type $pg_base $pg_count" 30); then
		pg_guest_rc=0
	else
		pg_guest_rc=$?
		for pg_pid in $pg_pids; do
			kill "$pg_pid" 2>/dev/null || true
		done
	fi
	pg_ok=0
	[ "$pg_guest_rc" -eq 0 ] &&
	    [ "$pg_guest_out" = "PASS parallel-echo-clients type=$pg_type count=$pg_count" ] ||
	    pg_ok=1
	pg_i=0
	for pg_pid in $pg_pids; do
		pg_listener_rc=0
		wait "$pg_pid" 2>/dev/null || pg_listener_rc=$?
		if [ "$pg_listener_rc" -ne 0 ]; then
			echo "  listener $pg_i status=$pg_listener_rc" >&2
			cat "$pg_dir/$pg_i.log" >&2 2>/dev/null || true
			pg_ok=1
		fi
		pg_i=$((pg_i + 1))
	done
	if [ "$pg_ok" -ne 0 ]; then
		diag_capture "parallel_${pg_type}_g2h_guest" "$pg_guest_rc" \
		    "$pg_guest_out"
	fi
	res "parallel_${pg_type}_g2h" "$pg_ok"
}

# A listener can report ready immediately before its REQUEST/RESPONSE reaches
# the host control path.  Retry only the device's explicit ECONNREFUSED status;
# every other connector error is returned immediately.
vshc() {
	_dir=$1
	_port=$2
	shift 2
	if [ "$BACKEND" = kernel ]; then
		_retry_status=3
	else
		_retry_status=4
	fi
	_try=0
	while [ "$_try" -lt 5 ]; do
		if [ "$BACKEND" = kernel ]; then
			timeout 20 "$TOOLS/vsock-pipe" "$@" "$GUEST_CID" "$_port"
		else
			timeout 20 "$TOOLS/vsh-connect" "$@" "$_dir" "$_port"
		fi
		_rc=$?
		[ "$_rc" -ne "$_retry_status" ] && return "$_rc"
		sleep 1
		_try=$((_try + 1))
	done
	return "$_retry_status"
}

host_listener() {
	_timeout=$1
	_port=$2
	shift 2
	if [ "$BACKEND" = kernel ]; then
		timeout "$_timeout" "$TOOLS/vsock-pipe" -l "$@" "$_port"
	else
		rm -f "$DIR/$_port"
		timeout "$_timeout" "$TOOLS/unix-pipe" -l "$@" "$DIR/$_port"
	fi
}

host_wait_disconnect() {
	_port=$1
	if [ "$BACKEND" = kernel ]; then
		"$TOOLS/vsock-pipe" -w "$GUEST_CID" "$_port"
	else
		"$TOOLS/vsh-connect" -w "$DIR" "$_port"
	fi
}

echo "vsock linux e2e: backend=$BACKEND DIR=$DIR REC=$REC"

case "$TRANSPORT" in
modern|legacy) ;;
*) echo "TRANSPORT must be modern or legacy" >&2; exit 2 ;;
esac
case "$GUEST_CID" in
''|*[!0-9]*) echo "GUEST_CID must be numeric" >&2; exit 2 ;;
esac
case "$BACKEND" in
userspace) ;;
kernel) ;;
*) echo "BACKEND must be userspace or kernel" >&2; exit 2 ;;
esac
case "$MODE" in
full|smoke|churn) ;;
*) echo "MODE must be full, smoke, or churn" >&2; exit 2 ;;
esac
case "$CHURN_CONNECTIONS" in
''|*[!0-9]*) echo "CHURN_CONNECTIONS must be an integer" >&2; exit 2 ;;
esac
[ "$CHURN_CONNECTIONS" -ge 2 ] && [ "$CHURN_CONNECTIONS" -le 64 ] || {
	echo "CHURN_CONNECTIONS must be in [2, 64]" >&2
	exit 2
}
case "$PORT_OFFSET" in
''|*[!0-9]*) echo "PORT_OFFSET must be a non-negative integer" >&2; exit 2 ;;
esac
[ "$PORT_OFFSET" -le 1000000 ] || {
	echo "PORT_OFFSET must not exceed 1000000" >&2
	exit 2
}

# A full matrix immediately precedes the soak loop.  Keep each soak iteration
# focused on the hot lifecycle paths so thousands of connections finish in
# minutes rather than rerunning slow reserved-CID and feature conformance
# probes.  Both socket types and directions are covered, and each successful
# worker proves connection, data integrity, orderly close, and endpoint reuse.
if [ "$MODE" = churn ]; then
	run_parallel_h2g stream "$((7200 + PORT_OFFSET))" "$CHURN_CONNECTIONS"
	run_parallel_h2g seq "$((7270 + PORT_OFFSET))" "$CHURN_CONNECTIONS"
	run_parallel_g2h stream "$((7340 + PORT_OFFSET))" "$CHURN_CONNECTIONS"
	run_parallel_g2h seq "$((7410 + PORT_OFFSET))" "$CHURN_CONNECTIONS"
	echo "----"
	echo "linux e2e churn: $PASS passed, $FAIL failed " \
	    "connections=$((4 * CHURN_CONNECTIONS))"
	[ "$FAIL" -eq 0 ] || dump_context
	exit "$FAIL"
fi

# Fail before the data tests unless the exact expected PCI function is uniquely
# bound to the upstream driver.  The helper also proves AF_VSOCK socket
# creation, so a similarly named but unbound device cannot satisfy preflight.
preflight_packed=
[ "$VSOCK_PACKED" = no ] || preflight_packed=" packed"
$ACMD "test -r $GPY && python3 $GPY preflight $TRANSPORT $GUEST_CID$preflight_packed" 20 || {
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
    [ "$reserved_out" != "PASS reserved-cids cid2-seq=ECONNRESET cid2-before=ECONNRESET cid0=ETIMEDOUT cid2-after=ECONNRESET" ]; then
	diag_capture reserved_cids "$reserved_rc" "$reserved_out"
	dump_context
	exit 2
fi
echo "PASS  preflight_reserved_cids"

# Repeatedly exercise the two refusal paths before opening a successful
# connection.  This catches leaked CONNECTING/control/provider state that a
# single failed connect cannot expose, and the smoke probes immediately below
# prove that the backend recovers rather than merely returning the expected
# errno.
for refused_type in stream seq; do
	if refused_out=$($ACMD \
	    "python3 $GPY refused-storm $refused_type $((7108 + PORT_OFFSET)) 32" 60); then
		refused_rc=0
	else
		refused_rc=$?
	fi
	[ "$refused_rc" -eq 0 ] &&
	    [ "$refused_out" = "PASS refused-connect-storm type=$refused_type attempts=32" ]
	ok=$?
	[ "$ok" -eq 0 ] ||
	    diag_capture "refused_storm_g2h_$refused_type" "$refused_rc" "$refused_out"
	res "refused_storm_g2h_$refused_type" "$ok"
done

if [ "$BACKEND" = kernel ]; then
	host_refused_status=3
else
	host_refused_status=4
fi
for refused_type in stream seq; do
	refused_flags=
	[ "$refused_type" = stream ] || refused_flags=-s
	refused_rc=0
	refused_count=0
	while [ "$refused_count" -lt 32 ]; do
		if [ "$BACKEND" = kernel ]; then
			timeout 5 "$TOOLS/vsock-pipe" $refused_flags \
			    "$GUEST_CID" "$((7108 + PORT_OFFSET))" \
			    </dev/null >/dev/null 2>&1
		else
			timeout 5 "$TOOLS/vsh-connect" $refused_flags \
			    "$DIR" "$((7108 + PORT_OFFSET))" \
			    </dev/null >/dev/null 2>&1
		fi
		refused_rc=$?
		[ "$refused_rc" -eq "$host_refused_status" ] || break
		refused_count=$((refused_count + 1))
	done
	[ "$refused_count" -eq 32 ] &&
	    [ "$refused_rc" -eq "$host_refused_status" ]
	ok=$?
	if [ "$ok" -ne 0 ]; then
		echo "  refused_storm_h2g_$refused_type: completed=$refused_count/32 rc=$refused_rc expected=$host_refused_status" >&2
	fi
	res "refused_storm_h2g_$refused_type" "$ok"
done

# Prove both socket types in both directions before running the larger matrix.
# In particular, lifecycle callers use this gate after checkpoint/restore, so
# the SEQPACKET probes independently prove that a reconstructed kernel provider
# received the restored transport feature epoch rather than merely accepting
# STREAM traffic under its attach-time defaults.  Every subsequent case
# depends on these same control and data paths; cascading failures after a
# smoke probe only obscure the root cause.
gbg "echo-l stream $((6991 + PORT_OFFSET))"
if smoke_out=$(printf 'VSOCK-SMOKE-H2G' |
    vshc "$DIR" "$((6991 + PORT_OFFSET))"); then
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

host_listener 20 "$((6992 + PORT_OFFSET))" -e -n 1 \
    >"$HOST_WORK/smoke-g2h.host.log" 2>&1 &
smoke_pid=$!
sleep 1
smoke_host_rc=0
if smoke_out=$($ACMD \
    "python3 $GPY send-echo stream $((6992 + PORT_OFFSET)) VSOCK-SMOKE-G2H" 15); then
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

gbg "echo-l seq $((6993 + PORT_OFFSET))"
if smoke_out=$(printf 'VSOCK-SMOKE-SEQ-H2G' |
    vshc "$DIR" "$((6993 + PORT_OFFSET))" -s); then
	smoke_rc=0
else
	smoke_rc=$?
fi
if [ "$smoke_rc" -ne 0 ] || [ "$smoke_out" != VSOCK-SMOKE-SEQ-H2G ]; then
	diag_capture smoke_seq_h2g "$smoke_rc" "$smoke_out"
	dump_context
	exit 2
fi
echo "PASS  preflight_seqpacket_data_h2g"

host_listener 20 "$((6994 + PORT_OFFSET))" -s -e -n 1 \
    >"$HOST_WORK/smoke-seq-g2h.host.log" 2>&1 &
smoke_pid=$!
sleep 1
smoke_host_rc=0
if smoke_out=$($ACMD \
    "python3 $GPY send-echo seq $((6994 + PORT_OFFSET)) VSOCK-SMOKE-SEQ-G2H" 15); then
	smoke_rc=0
else
	smoke_rc=$?
fi
wait "$smoke_pid" 2>/dev/null || smoke_host_rc=$?
if [ "$smoke_rc" -ne 0 ] || [ "$smoke_host_rc" -ne 0 ] ||
    [ "$smoke_out" != "ECHO VSOCK-SMOKE-SEQ-G2H" ]; then
	diag_capture smoke_seq_g2h "$smoke_rc" "$smoke_out"
	echo "  host listener rc=$smoke_host_rc" >&2
	cat "$HOST_WORK/smoke-seq-g2h.host.log" >&2 || true
	dump_context
	exit 2
fi
echo "PASS  preflight_seqpacket_data_g2h"

if [ "$MODE" = smoke ]; then
	echo "----"
	echo "linux e2e smoke: 4 passed, 0 failed"
	exit 0
fi

# Exercise shared connection tables, virtqueues, provider queues, credit
# wakeups, and simultaneous teardown.  Each worker uses a distinct endpoint
# and payload, and success requires every endpoint on both sides to complete.
run_parallel_h2g stream "$((7200 + PORT_OFFSET))" 8
run_parallel_h2g seq "$((7210 + PORT_OFFSET))" 8
run_parallel_g2h stream "$((7220 + PORT_OFFSET))" 8
run_parallel_g2h seq "$((7230 + PORT_OFFSET))" 8

# --- host->guest (guest is the server) ---
gbg "echo-l stream $((7001 + PORT_OFFSET))"
if out=$(printf 'E2E-H2G-STREAM' |
    vshc "$DIR" "$((7001 + PORT_OFFSET))"); then
	rc=0
else
	rc=$?
fi
[ "$rc" -eq 0 ] && [ "$out" = "E2E-H2G-STREAM" ]
ok=$?
[ "$ok" -eq 0 ] || diag_capture stream_echo_h2g "$rc" "$out"
res stream_echo_h2g "$ok"

gbg "echo-l seq $((7002 + PORT_OFFSET))"
if out=$(printf 'E2E-H2G-SEQ' |
    vshc "$DIR" "$((7002 + PORT_OFFSET))" -s); then
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
gbg "close-l seq $((7010 + PORT_OFFSET)) $close_token"
if out=$(printf %s "$close_token" |
    vshc "$DIR" "$((7010 + PORT_OFFSET))" -s); then
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

# STREAM uses byte-oriented receive and a different relay path from
# SEQPACKET.  Verify the same bidirectional half-close contract explicitly
# rather than assuming the SEQPACKET result covers it.
close_token=E2E-H2G-STREAM-CLOSE
gbg "close-l stream $((7014 + PORT_OFFSET)) $close_token"
if out=$(printf %s "$close_token" |
    vshc "$DIR" "$((7014 + PORT_OFFSET))"); then
	rc=0
else
	rc=$?
fi
sleep 1
if o=$(gout); then guest_rc=0; else guest_rc=$?; fi
printf '%s\n' "$o" | grep -q '^PASS graceful-close-listener type=stream$' &&
    [ "$rc" -eq 0 ] && [ "$guest_rc" -eq 0 ] && [ -z "$out" ]
ok=$?
if [ "$ok" -ne 0 ]; then
	diag_capture stream_graceful_close_h2g "$rc" "$o"
	echo "  guest status=$guest_rc host-bytes=$(printf %s "$out" | wc -c | tr -d ' ')" >&2
fi
res stream_graceful_close_h2g "$ok"

gbg "recv-l seq $((7003 + PORT_OFFSET))"
if head -c "$REC" /dev/zero | tr '\0' A |
    vshc "$DIR" "$((7003 + PORT_OFFSET))" -s -1 >/dev/null; then
	rc=0
else
	rc=$?
fi
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

gbg "recv-l stream $((7004 + PORT_OFFSET))"
if head -c "$REC" /dev/zero | tr '\0' B |
    vshc "$DIR" "$((7004 + PORT_OFFSET))" -1 >/dev/null; then
	rc=0
else
	rc=$?
fi
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
host_listener 20 "$((7005 + PORT_OFFSET))" -e -n 1 \
    >"$HOST_WORK/7005.listener.log" 2>&1 &
lpid=$!
sleep 1
if o=$($ACMD \
    "python3 $GPY send-echo stream $((7005 + PORT_OFFSET)) E2E-G2H-STREAM" 15); then
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

host_listener 20 "$((7006 + PORT_OFFSET))" -s -e -n 1 \
    >"$HOST_WORK/7006.listener.log" 2>&1 &
lpid=$!
sleep 1
if o=$($ACMD \
    "python3 $GPY send-echo seq $((7006 + PORT_OFFSET)) E2E-G2H-SEQ" 15); then
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
host_listener 20 "$((7011 + PORT_OFFSET))" -s -d \
    >"$HOST_WORK/7011.close.out" 2>"$HOST_WORK/7011.listener.log" &
lpid=$!
sleep 1
if o=$($ACMD \
    "python3 $GPY close seq $((7011 + PORT_OFFSET)) $close_token" 15); then
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

close_token=E2E-G2H-STREAM-CLOSE
host_listener 20 "$((7015 + PORT_OFFSET))" -d \
    >"$HOST_WORK/7015.close.out" 2>"$HOST_WORK/7015.listener.log" &
lpid=$!
sleep 1
if o=$($ACMD \
    "python3 $GPY close stream $((7015 + PORT_OFFSET)) $close_token" 15); then
	guest_rc=0
else
	guest_rc=$?
fi
listener_rc=0; wait "$lpid" 2>/dev/null || listener_rc=$?
if close_out=$(cat "$HOST_WORK/7015.close.out"); then host_read_rc=0; else host_read_rc=$?; fi
[ "$guest_rc" -eq 0 ] && [ "$listener_rc" -eq 0 ] &&
    [ "$host_read_rc" -eq 0 ] && [ "$close_out" = "$close_token" ] &&
    [ "$o" = 'PASS graceful-close-client type=stream' ]
ok=$?
if [ "$ok" -ne 0 ]; then
	diag_capture stream_graceful_close_g2h "$guest_rc" "$o"
	echo "  listener status=$listener_rc read-status=$host_read_rc" >&2
	diag_capture stream_graceful_close_g2h_payload "$host_read_rc" "$close_out"
	cat "$HOST_WORK/7015.listener.log" >&2 || true
fi
res stream_graceful_close_g2h "$ok"

# Kill the established host endpoint without shutdown/close cooperation.  The
# guest must observe EOF or reset promptly, and a fresh connection afterward
# proves the device remains usable.
gbg "abrupt-l stream $((7012 + PORT_OFFSET))"
abrupt_log="$HOST_WORK/7012.abrupt.log"
host_wait_disconnect "$((7012 + PORT_OFFSET))" >"$abrupt_log" 2>&1 &
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

gbg "echo-l stream $((7013 + PORT_OFFSET))"
if out=$(printf 'E2E-AFTER-HOST-KILL' |
    vshc "$DIR" "$((7013 + PORT_OFFSET))"); then
	rc=0
else
	rc=$?
fi
[ "$rc" -eq 0 ] && [ "$out" = "E2E-AFTER-HOST-KILL" ]
ok=$?
[ "$ok" -eq 0 ] || diag_capture after_abrupt_host_kill "$rc" "$out"
res after_abrupt_host_kill "$ok"

host_listener 30 "$((7007 + PORT_OFFSET))" -s -d \
    > "$HOST_WORK/g2h.seq.out" 2>"$HOST_WORK/7007.listener.log" &
lpid=$!
sleep 1
if $ACMD \
    "python3 $GPY send seq $((7007 + PORT_OFFSET)) $REC" 20 >/dev/null; then
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

host_listener 30 "$((7008 + PORT_OFFSET))" -d \
    > "$HOST_WORK/g2h.stream.out" 2>"$HOST_WORK/7008.listener.log" &
lpid=$!
sleep 1
if $ACMD \
    "python3 $GPY send stream $((7008 + PORT_OFFSET)) $REC" 20 >/dev/null; then
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
