#!/bin/sh
# vsock end-to-end test driver: 5BSD host <-> bhyve guest over the
# virtio-vsock device.  Covers the vsock_bhyve_testplan.md section-6
# matrix rows that in-guest ATF cannot (real wire, real device).
#
# Requirements:
#   - a running guest (CID 3) with the vsock device at path=$DIR
#   - $VCMD: command that runs its 1st arg as a shell command in the
#     guest and prints its stdout (the rig's console helper)
#   - /root/vsock-pipe present in the guest (baked into the image or
#     bootstrapped over the console)
#   - unix-pipe and vsh-connect built next to this script ($TOOLS)
#
# Usage: sh run.sh [test...]   (default: all)
set -u

DIR=${DIR:-$HOME/vm/vsock-sockdir}
VCMD=${VCMD:-"sh $HOME/vm/vcmd.sh"}
TOOLS=${TOOLS:-$(cd "$(dirname "$0")" && pwd)}
WORK=${WORK:-$(mktemp -d)}
BULK_MB=${BULK_MB:-256}
NCONN=${NCONN:-64}

PASS=0; FAIL=0; FAILED=""

result() { # <name> <0=pass>
	if [ "$2" -eq 0 ]; then
		echo "PASS  $1"; PASS=$((PASS + 1))
	else
		echo "FAIL  $1"; FAIL=$((FAIL + 1)); FAILED="$FAILED $1"
	fi
}

gcmd() { $VCMD "$1" "${2:-30}"; }

# Kill stray guest-side test processes so a leaked listener from a prior
# test cannot accept a later test's connection or clog the console.
gclean() { gcmd 'pkill -9 vsock-pipe 2>/dev/null; rm -f /tmp/conc.* 2>/dev/null; echo ok' 15 >/dev/null; }

# Host->guest connect with retry: the guest listener may not have bound
# when we first connect (ECONNREFUSED -> vsh-connect exit 4).  Retry a few
# times before giving up.  Args after the port are extra vsh-connect args.
vshc() {
	_dir=$1; _port=$2; shift 2
	_try=0
	while [ $_try -lt 10 ]; do
		timeout 250 "$TOOLS/vsh-connect" "$@" "$_dir" "$_port"
		_rc=$?
		[ $_rc -ne 4 ] && return $_rc
		sleep 1; _try=$((_try + 1))
	done
	return 4
}

# --- T1: STREAM echo guest->host -----------------------------------
t_echo_g2h() {
	(printf '' | timeout 20 "$TOOLS/unix-pipe" -l -e -n 1 "$DIR/5001" &)
	sleep 1
	out=$(gcmd 'timeout 15 sh -c "echo E2E-G2H | /root/vsock-pipe 2 5001"')
	[ "$out" = "E2E-G2H" ]; result stream_echo_g2h $?
}

# --- T2: STREAM echo host->guest (control socket) ------------------
t_echo_h2g() {
	gclean
	gcmd 'pkill vsock-pipe; nohup /root/vsock-pipe -l -e 5002 >/dev/null 2>&1 & sleep 1; echo up' >/dev/null
	out=$(printf 'E2E-H2G\n' | vshc "$DIR" 5002)
	[ "$out" = "E2E-H2G" ]; result stream_echo_h2g $?
}

# --- T3: SEQPACKET echo guest->host --------------------------------
t_seq_g2h() {
	(printf '' | timeout 20 "$TOOLS/unix-pipe" -l -s -e -n 1 "$DIR/5003" &)
	sleep 1
	out=$(gcmd 'timeout 15 sh -c "echo E2E-SEQ-G2H | /root/vsock-pipe -s 2 5003"')
	[ "$out" = "E2E-SEQ-G2H" ]; result seqpacket_echo_g2h $?
}

# --- T4: SEQPACKET echo host->guest --------------------------------
t_seq_h2g() {
	gclean
	gcmd 'nohup /root/vsock-pipe -l -s -e 5004 >/dev/null 2>&1 & sleep 1; echo up' >/dev/null
	out=$(printf 'E2E-SEQ-H2G\n' | vshc "$DIR" 5004 -s)
	[ "$out" = "E2E-SEQ-H2G" ]; result seqpacket_echo_h2g $?
}

# --- T5: bulk transfer guest->host, sha256 compare -----------------
t_bulk_g2h() {
	timeout 300 "$TOOLS/unix-pipe" -l -d "$DIR/5005" > "$WORK/bulk-g2h" &
	lpid=$!
	sleep 1
	gsum=$(gcmd "dd if=/dev/random of=/tmp/bulk bs=1m count=$BULK_MB 2>/dev/null; sha256 -q /tmp/bulk" 240)
	gcmd "timeout 220 /root/vsock-pipe 2 5005 < /tmp/bulk" 240 >/dev/null
	wait $lpid
	hsum=$(sha256sum "$WORK/bulk-g2h" 2>/dev/null | awk '{print $1}')
	gcmd 'rm -f /tmp/bulk' 15 >/dev/null
	[ -n "$gsum" ] && [ "$gsum" = "$hsum" ]; result "bulk_g2h_${BULK_MB}MiB" $?
}

# --- T6: bulk transfer host->guest, sha256 compare -----------------
t_bulk_h2g() {
	gclean
	gcmd 'nohup sh -c "/root/vsock-pipe -l -d 5006 > /tmp/rx" >/dev/null 2>&1 & sleep 1; echo up' >/dev/null
	dd if=/dev/urandom of="$WORK/bulk-h2g" bs=1048576 count="$BULK_MB" 2>/dev/null
	hsum=$(sha256sum "$WORK/bulk-h2g" | awk '{print $1}')
	vshc "$DIR" 5006 < "$WORK/bulk-h2g" >/dev/null
	sleep 2
	gsum=$(gcmd 'sha256 -q /tmp/rx' 120)
	gcmd 'rm -f /tmp/rx' 15 >/dev/null
	[ -n "$gsum" ] && [ "$gsum" = "$hsum" ]; result "bulk_h2g_${BULK_MB}MiB" $?
}

# --- T7: credit churn: many tiny writes guest->host ----------------
t_credit_churn() {
	timeout 120 "$TOOLS/unix-pipe" -l -d "$DIR/5007" > "$WORK/churn" &
	lpid=$!
	sleep 1
	gcmd 'timeout 100 sh -c "dd if=/dev/zero bs=16 count=20000 2>/dev/null | /root/vsock-pipe 2 5007"' 120 >/dev/null
	wait $lpid
	sz=$(wc -c < "$WORK/churn")
	[ "$sz" -eq 320000 ]; result credit_churn_20000x16 $?
}

# --- T8: connect to dead host port fails fast ----------------------
t_dead_host_port() {
	out=$(gcmd '/root/vsock-pipe 2 5999 </dev/null >/dev/null 2>&1; echo rc=$?' 15)
	[ "$out" = "rc=3" ]; result dead_host_port_econnreset $?
}

# --- T9: connect to dead guest port fails fast ---------------------
t_dead_guest_port() {
	printf '' | timeout 15 "$TOOLS/vsh-connect" "$DIR" 5998 >/dev/null 2>&1
	[ $? -eq 4 ]; result dead_guest_port_refused $?
}

# --- T10: concurrent connections guest->host -----------------------
t_concurrency() {
	gclean
	timeout 90 "$TOOLS/unix-pipe" -l -e -n "$NCONN" "$DIR/5010" &
	lpid=$!
	sleep 1
	out=$(gcmd "/root/vsock-conntest 2 5010 $NCONN" 90)
	wait $lpid 2>/dev/null
	[ "$out" = "ok=$NCONN" ]; result "concurrency_${NCONN}_conns" $?
}

# --- T11: EOF propagation guest->host ------------------------------
t_eof() {
	gclean
	start=$(date +%s)
	timeout 15 "$TOOLS/unix-pipe" -l -d "$DIR/5011" > /dev/null &
	lpid=$!
	sleep 1
	gcmd 'timeout 10 /root/vsock-pipe 2 5011 </dev/null >/dev/null 2>&1; echo done' >/dev/null
	wait $lpid
	rc=$?
	end=$(date +%s)
	[ $rc -eq 0 ] && [ $((end - start)) -lt 10 ]; result eof_propagation $?
}

# --- T12: SIGKILL sender mid-transfer; device survives -------------
t_kill_midsend() {
	gclean
	timeout 60 "$TOOLS/unix-pipe" -l -d "$DIR/5012" > /dev/null &
	lpid=$!
	sleep 1
	gcmd 'dd if=/dev/zero bs=1m count=1024 2>/dev/null | /root/vsock-pipe 2 5012 & sleep 1; pkill -9 -f "vsock-pipe 2 5012"; echo killed' >/dev/null
	# listener must see EOF/reset promptly, not hang for the timeout
	start=$(date +%s); wait $lpid 2>/dev/null; end=$(date +%s)
	surv=1
	if [ $((end - start)) -lt 20 ]; then
		# device must still work afterwards
		(printf '' | timeout 15 "$TOOLS/unix-pipe" -l -e -n 1 "$DIR/5013" &)
		sleep 1
		out=$(gcmd 'timeout 15 sh -c "echo ALIVE | /root/vsock-pipe 2 5013"' 20)
		[ "$out" = "ALIVE" ] && surv=0
	fi
	result kill_midsend_teardown $surv
}

# --- T13: SEQPACKET multi-record delivery over the wire ------------
t_seq_records() {
	gclean
	timeout 30 "$TOOLS/unix-pipe" -l -s -d "$DIR/5014" > "$WORK/seqsz" &
	lpid=$!
	sleep 1
	# Two distinct records (separate writes) must arrive as two
	# records; payload concatenation checked here, boundary
	# semantics are covered by the in-guest ATF suite.
	gcmd 'timeout 20 sh -c "{ printf A; sleep 1; printf BB; } | /root/vsock-pipe -s 2 5014"' 30 >/dev/null
	wait $lpid 2>/dev/null
	got=$(cat "$WORK/seqsz" 2>/dev/null)
	[ "$got" = "ABB" ]; result seqpacket_records_wire $?
}

# --- T14b: a large host->guest SEQPACKET record (> old 64 KiB relay buffer)
# arrives as ONE record, not shredded/split.  Uses vsock-recrx (one recv per
# record) so record FRAMING is visible -- byte-stream tools cannot see this.
# Exercises the relay socket-buffer sizing (VTVSOCK_BUF_ALLOC) end to end. ---
t_seq_bigrecord() {
	gclean
	gcmd 'pkill -9 vsock-recrx 2>/dev/null; rm -f /tmp/recrx.out;
	      nohup /root/vsock-recrx 5016 >/tmp/recrx.out 2>&1 &
	      sleep 1; echo up' >/dev/null
	# One 200 KiB record via a single sendmsg(MSG_EOR) (vsh-connect -1).
	head -c 204800 /dev/zero | tr '\0' A | vshc "$DIR" 5016 -s -1 >/dev/null
	sleep 1
	out=$(gcmd 'cat /tmp/recrx.out; pkill -9 vsock-recrx 2>/dev/null' 15)
	# Exactly one RECORD line, of the full length -- not several short ones.
	nrec=$(printf '%s\n' "$out" | grep -c '^RECORD ')
	printf '%s\n' "$out" | grep -q '^RECORD len=204800$' && [ "$nrec" = 1 ]
	result seqpacket_bigrecord_whole $?
}

# --- T14: connection-count leak check (must return to baseline) ----
t_leak_check() {
	gclean
	base=$(gcmd 'sysctl -n kern.vsock.cur_connections' 15)
	(printf '' | timeout 20 "$TOOLS/unix-pipe" -l -e -n 1 "$DIR/5015" &)
	sleep 1
	gcmd 'timeout 15 sh -c "echo LEAK | /root/vsock-pipe 2 5015"' >/dev/null
	sleep 2
	after=$(gcmd 'sysctl -n kern.vsock.cur_connections' 15)
	[ -n "$base" ] && [ "$after" = "$base" ]; result leak_check_conn_count $?
}

ALL="t_echo_g2h t_echo_h2g t_seq_g2h t_seq_h2g t_bulk_g2h t_bulk_h2g
     t_credit_churn t_dead_host_port t_dead_guest_port t_concurrency
     t_eof t_kill_midsend t_seq_records t_seq_bigrecord t_leak_check"

echo "vsock e2e: DIR=$DIR BULK=${BULK_MB}MiB NCONN=$NCONN"
gcmd 'test -x /root/vsock-pipe && echo tool-ok' | grep -q tool-ok || {
	echo "guest is missing /root/vsock-pipe -- bake it into the image" >&2
	exit 2
}

for t in ${*:-$ALL}; do
	$t
done

echo "----"
echo "e2e: $PASS passed, $FAIL failed${FAILED:+ --$FAILED}"
rm -rf "$WORK"
[ "$FAIL" -eq 0 ]
