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
# Env: DIR, TOOLS, ACMD, GPY (guest path to gvsock.py), REC (record size bytes),
# TRANSPORT (modern or legacy, used to validate the PCI identity).
set -u

DIR=${DIR:-$HOME/vm/vsock-sockdir-linux}
TOOLS=${TOOLS:-$(cd "$(dirname "$0")" && pwd)}
ACMD=${ACMD:-"sh $HOME/vm/acmd.sh"}
GPY=${GPY:-/tmp/gvsock.py}
REC=${REC:-204800}
TRANSPORT=${TRANSPORT:-modern}
HOST_WORK=${HOST_WORK:-${TMPDIR:-/tmp}/vsock-linux-e2e.$$}
mkdir -p "$HOST_WORK"

PASS=0; FAIL=0; FAILED=""
res() {
	if [ "$2" -eq 0 ]; then echo "PASS  $1"; PASS=$((PASS + 1))
	else echo "FAIL  $1"; FAIL=$((FAIL + 1)); FAILED="$FAILED $1"; fi
}
# Start a backgrounded guest helper (server), wait for its "up" line.
gbg() { $ACMD "pkill -9 python3 2>/dev/null; rm -f /tmp/g.out; \
	nohup python3 $GPY $1 >/tmp/g.out 2>&1 & \
	i=0; while ! grep -q '^up$' /tmp/g.out 2>/dev/null && [ \"\$i\" -lt 10 ]; \
	do sleep 1; i=\$((i + 1)); done; grep -q '^up$' /tmp/g.out" 15 >/dev/null; }
gout() { $ACMD 'cat /tmp/g.out; pkill -9 python3 2>/dev/null' 12; }

echo "vsock linux e2e: DIR=$DIR REC=$REC"

case "$TRANSPORT" in
modern) expected_device=0x1053 ;;
legacy) expected_device=0x1013 ;;
*) echo "TRANSPORT must be modern or legacy" >&2; exit 2 ;;
esac

# Fail before the data tests if Alpine did not bind the upstream driver or if
# bhyve exposed the wrong opt-in/default PCI identity.
$ACMD "test -r $GPY && python3 -c 'import socket; s=socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM); s.close()' && \
set -- /sys/bus/virtio/drivers/*vsock*; test -d \"\$1\" && \
found=no; for v in /sys/bus/pci/devices/*/vendor; do \
[ \"\$(cat \"\$v\")\" = 0x1af4 ] || continue; d=\${v%/vendor}/device; \
[ \"\$(cat \"\$d\")\" = '$expected_device' ] && found=yes && break; done; \
[ \"\$found\" = yes ]" 20 >/dev/null || {
	echo "Alpine preflight failed: helper, driver binding, or PCI identity" >&2
	exit 2
}

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
rm -f "$DIR/7005"; timeout 20 "$TOOLS/unix-pipe" -l -e -n 1 "$DIR/7005" >/dev/null 2>&1 &
lpid=$!
sleep 1
o=$($ACMD "python3 $GPY send-echo stream 7005 E2E-G2H-STREAM" 15)
wait "$lpid" 2>/dev/null
echo "$o" | grep -q 'ECHO E2E-G2H-STREAM'; res stream_echo_g2h $?

rm -f "$DIR/7006"; timeout 20 "$TOOLS/unix-pipe" -l -s -e -n 1 "$DIR/7006" >/dev/null 2>&1 &
lpid=$!
sleep 1
o=$($ACMD "python3 $GPY send-echo seq 7006 E2E-G2H-SEQ" 15)
wait "$lpid" 2>/dev/null
echo "$o" | grep -q 'ECHO E2E-G2H-SEQ'; res seqpacket_echo_g2h $?

rm -f "$DIR/7007"; timeout 30 "$TOOLS/unix-pipe" -l -s -d "$DIR/7007" \
    > "$HOST_WORK/g2h.seq.out" 2>/dev/null &
lpid=$!
sleep 1
$ACMD "python3 $GPY send seq 7007 $REC" 20 >/dev/null
wait "$lpid" 2>/dev/null
got=$(wc -c < "$HOST_WORK/g2h.seq.out" | tr -d ' '); [ "$got" = "$REC" ]; res seqpacket_bigrecord_g2h $?

rm -f "$DIR/7008"; timeout 30 "$TOOLS/unix-pipe" -l -d "$DIR/7008" \
    > "$HOST_WORK/g2h.stream.out" 2>/dev/null &
lpid=$!
sleep 1
$ACMD "python3 $GPY send stream 7008 $REC" 20 >/dev/null
wait "$lpid" 2>/dev/null
got=$(wc -c < "$HOST_WORK/g2h.stream.out" | tr -d ' '); [ "$got" = "$REC" ]; res stream_bulk_g2h $?

echo "----"
echo "linux e2e: $PASS passed, $FAIL failed$( [ -n "$FAILED" ] && echo " ($FAILED )" )"
[ "$FAIL" -eq 0 ]
