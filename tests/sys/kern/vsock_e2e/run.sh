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

# --- T1: STREAM echo guest->host -----------------------------------
t_echo_g2h() {
	(printf '' | timeout 20 "$TOOLS/unix-pipe" -l -e -n 1 "$DIR/5001" &)
	sleep 1
	out=$(gcmd 'timeout 15 sh -c "echo E2E-G2H | /root/vsock-pipe 2 5001"')
	[ "$out" = "E2E-G2H" ]; result stream_echo_g2h $?
}

# --- T2: STREAM echo host->guest (control socket) ------------------
t_echo_h2g() {
	gcmd 'pkill vsock-pipe; nohup /root/vsock-pipe -l -e 5002 >/dev/null 2>&1 & sleep 1; echo up' >/dev/null
	out=$(printf 'E2E-H2G\n' | timeout 20 "$TOOLS/vsh-connect" "$DIR" 5002)
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
	gcmd 'nohup /root/vsock-pipe -l -s -e 5004 >/dev/null 2>&1 & sleep 1; echo up' >/dev/null
	out=$(printf 'E2E-SEQ-H2G\n' | timeout 20 "$TOOLS/vsh-connect" -s "$DIR" 5004)
	[ "$out" = "E2E-SEQ-H2G" ]; result seqpacket_echo_h2g $?
}

# --- T5: bulk transfer guest->host, sha256 compare -----------------
t_bulk_g2h() {
	timeout 300 "$TOOLS/unix-pipe" -l "$DIR/5005" > "$WORK/bulk-g2h" &
	lpid=$!
	sleep 1
	gsum=$(gcmd "dd if=/dev/random of=/tmp/bulk bs=1m count=$BULK_MB 2>/dev/null; sha256 -q /tmp/bulk" 240)
	gcmd "timeout 220 /root/vsock-pipe 2 5005 < /tmp/bulk" 240 >/dev/null
	wait $lpid
	hsum=$(sha256sum "$WORK/bulk-g2h" 2>/dev/null | awk '{print $1}')
	[ -n "$gsum" ] && [ "$gsum" = "$hsum" ]; result "bulk_g2h_${BULK_MB}MiB" $?
}

# --- T6: bulk transfer host->guest, sha256 compare -----------------
t_bulk_h2g() {
	gcmd 'nohup sh -c "/root/vsock-pipe -l 5006 > /tmp/rx" >/dev/null 2>&1 & sleep 1; echo up' >/dev/null
	dd if=/dev/urandom of="$WORK/bulk-h2g" bs=1048576 count="$BULK_MB" 2>/dev/null
	hsum=$(sha256sum "$WORK/bulk-h2g" | awk '{print $1}')
	timeout 300 "$TOOLS/vsh-connect" "$DIR" 5006 < "$WORK/bulk-h2g" >/dev/null
	sleep 2
	gsum=$(gcmd 'sha256 -q /tmp/rx' 120)
	[ -n "$gsum" ] && [ "$gsum" = "$hsum" ]; result "bulk_h2g_${BULK_MB}MiB" $?
}

# --- T7: credit churn: many tiny writes guest->host ----------------
t_credit_churn() {
	timeout 120 "$TOOLS/unix-pipe" -l "$DIR/5007" > "$WORK/churn" &
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
	timeout 60 "$TOOLS/unix-pipe" -l -e -n "$NCONN" "$DIR/5010" &
	lpid=$!
	sleep 1
	out=$(gcmd 'i=0; ok=0; while [ $i -lt '"$NCONN"' ]; do
	    ( timeout 30 sh -c "echo tok-$i | /root/vsock-pipe 2 5010" > /tmp/conc.$i ) &
	    i=$((i+1)); done; wait
	    i=0; while [ $i -lt '"$NCONN"' ]; do
	    [ "$(cat /tmp/conc.$i)" = "tok-$i" ] && ok=$((ok+1));
	    i=$((i+1)); done; rm -f /tmp/conc.*; echo ok=$ok' 60)
	wait $lpid 2>/dev/null
	[ "$out" = "ok=$NCONN" ]; result "concurrency_${NCONN}_conns" $?
}

# --- T11: EOF propagation guest->host ------------------------------
t_eof() {
	start=$(date +%s)
	timeout 15 "$TOOLS/unix-pipe" -l "$DIR/5011" > /dev/null &
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
	timeout 60 "$TOOLS/unix-pipe" -l "$DIR/5012" > /dev/null &
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

ALL="t_echo_g2h t_echo_h2g t_seq_g2h t_seq_h2g t_bulk_g2h t_bulk_h2g
     t_credit_churn t_dead_host_port t_dead_guest_port t_concurrency
     t_eof t_kill_midsend"

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
