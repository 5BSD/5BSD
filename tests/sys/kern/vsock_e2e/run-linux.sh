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
#   - unix-pipe and vsh-connect built next to this script ($TOOLS)
#
# Env: DIR, TOOLS, ACMD, GPY (guest path to gvsock.py), REC (record size bytes).
set -u

DIR=${DIR:-$HOME/vm/vsock-sockdir-linux}
TOOLS=${TOOLS:-$(cd "$(dirname "$0")" && pwd)}
ACMD=${ACMD:-"sh $HOME/vm/acmd.sh"}
GPY=${GPY:-/tmp/gvsock.py}
REC=${REC:-204800}

PASS=0; FAIL=0; FAILED=""
res() {
	if [ "$2" -eq 0 ]; then echo "PASS  $1"; PASS=$((PASS + 1))
	else echo "FAIL  $1"; FAIL=$((FAIL + 1)); FAILED="$FAILED $1"; fi
}
# Start a backgrounded guest helper (server), wait for its "up" line.
gbg() { $ACMD "pkill -9 python3 2>/dev/null; rm -f /tmp/g.out; \
	nohup python3 $GPY $1 >/tmp/g.out 2>&1 & sleep 1.5; echo up" 15 >/dev/null; }
gout() { $ACMD 'cat /tmp/g.out; pkill -9 python3 2>/dev/null' 12; }

echo "vsock linux e2e: DIR=$DIR REC=$REC"

# --- host->guest (guest is the server) ---
gbg "echo-l stream 7001"
out=$(printf 'E2E-H2G-STREAM' | timeout 12 "$TOOLS/vsh-connect" "$DIR" 7001)
[ "$out" = "E2E-H2G-STREAM" ]; res stream_echo_h2g $?

gbg "echo-l seq 7002"
out=$(printf 'E2E-H2G-SEQ' | timeout 12 "$TOOLS/vsh-connect" -s "$DIR" 7002)
[ "$out" = "E2E-H2G-SEQ" ]; res seqpacket_echo_h2g $?

gbg "recv-l seq 7003"
head -c "$REC" /dev/zero | tr '\0' A | \
	timeout 15 "$TOOLS/vsh-connect" -s -1 "$DIR" 7003 >/dev/null
sleep 1; o=$(gout)
echo "$o" | grep -q "RECORD len=$REC" && [ "$(echo "$o" | grep -c '^RECORD')" = 1 ]
res seqpacket_bigrecord_h2g $?

gbg "recv-l stream 7004"
head -c "$REC" /dev/zero | tr '\0' B | \
	timeout 15 "$TOOLS/vsh-connect" -1 "$DIR" 7004 >/dev/null
sleep 1; o=$(gout); echo "$o" | grep -q "bytes=$REC"; res stream_bulk_h2g $?

# --- guest->host (host is the server) ---
rm -f "$DIR/7005"; timeout 20 "$TOOLS/unix-pipe" -l -e "$DIR/7005" >/dev/null 2>&1 &
sleep 1
o=$($ACMD "python3 $GPY send-echo stream 7005 E2E-G2H-STREAM" 15)
echo "$o" | grep -q 'ECHO E2E-G2H-STREAM'; res stream_echo_g2h $?

rm -f "$DIR/7006"; timeout 20 "$TOOLS/unix-pipe" -l -s -e "$DIR/7006" >/dev/null 2>&1 &
sleep 1
o=$($ACMD "python3 $GPY send-echo seq 7006 E2E-G2H-SEQ" 15)
echo "$o" | grep -q 'ECHO E2E-G2H-SEQ'; res seqpacket_echo_g2h $?

rm -f "$DIR/7007"; timeout 30 "$TOOLS/unix-pipe" -l -s -d "$DIR/7007" > /tmp/g2h.out 2>/dev/null &
sleep 1
$ACMD "python3 $GPY send seq 7007 $REC" 20 >/dev/null; sleep 1
got=$(wc -c < /tmp/g2h.out | tr -d ' '); [ "$got" = "$REC" ]; res seqpacket_bigrecord_g2h $?

rm -f "$DIR/7008"; timeout 30 "$TOOLS/unix-pipe" -l -d "$DIR/7008" > /tmp/g2hs.out 2>/dev/null &
sleep 1
$ACMD "python3 $GPY send stream 7008 $REC" 20 >/dev/null; sleep 1
got=$(wc -c < /tmp/g2hs.out | tr -d ' '); [ "$got" = "$REC" ]; res stream_bulk_g2h $?

echo "----"
echo "linux e2e: $PASS passed, $FAIL failed$( [ -n "$FAILED" ] && echo " ($FAILED )" )"
[ "$FAIL" -eq 0 ]
