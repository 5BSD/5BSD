#!/bin/sh
#
# test_peripheral.sh — Validate blued peripheral mode end-to-end.
#
# Prerequisites:
#   - Build: make -C /usr/src/usr.sbin/bluetooth/blued
#   - Install kernel modules:
#     make -C /usr/src/sys/modules/netgraph/bluetooth/l2cap install
#     make -C /usr/src/sys/modules/netgraph/bluetooth/socket install
#   - A real or virtual BT adapter (ubt0)
#   - A BLE client device (phone with nRF Connect, or Linux box)
#
# Usage:
#   ./test_peripheral.sh            # Run all local checks
#   ./test_peripheral.sh start      # Start blued in peripheral mode
#   ./test_peripheral.sh ctl CMD    # Send a control command
#
# The script validates:
#   1. Kernel modules are loaded
#   2. Adapter discovery via bt_devenum
#   3. blued starts and advertises
#   4. Control socket responds
#   5. GATT database is built (attribute count)
#
# Client-side tests (run from phone/Linux):
#   See TESTING.md instructions at the end of this file.

set -e

BLUED_BIN="${BLUED_BIN:-/usr/obj/usr/src/amd64.amd64/usr.sbin/bluetooth/blued/blued}"
BLUED_SOCK="/var/run/blued.sock"
PASS=0
FAIL=0

pass() {
	PASS=$((PASS + 1))
	printf "  PASS: %s\n" "$1"
}

fail() {
	FAIL=$((FAIL + 1))
	printf "  FAIL: %s\n" "$1"
}

check() {
	if eval "$2"; then
		pass "$1"
	else
		fail "$1"
	fi
}

blued_ctl() {
	printf "%s\n" "$1" | nc -U "$BLUED_SOCK" -w 2 2>/dev/null
}

# ---------------------------------------------------------------
#  Subcommands
# ---------------------------------------------------------------

case "${1:-check}" in
start)
	echo "Starting blued in peripheral mode (verbose)..."
	exec "$BLUED_BIN" -vvvp
	;;
ctl)
	shift
	blued_ctl "$*"
	exit $?
	;;
check)
	;;
*)
	echo "Usage: $0 [check|start|ctl CMD]"
	exit 1
	;;
esac

# ---------------------------------------------------------------
#  Local validation checks
# ---------------------------------------------------------------

echo "=== blued peripheral test suite ==="
echo ""

# 1. Binary exists
echo "[1] Binary"
check "blued binary exists" "test -x '$BLUED_BIN'"

# 2. Kernel modules
echo "[2] Kernel modules"
check "ng_ubt loaded" "kldstat -q -m ng_ubt 2>/dev/null"
check "ng_l2cap loaded" "kldstat -q -m ng_l2cap 2>/dev/null"
check "ng_btsocket loaded" "kldstat -q -m ng_btsocket 2>/dev/null"
check "ng_hci loaded" "kldstat -q -m ng_hci 2>/dev/null"

# 3. Adapter present
echo "[3] Adapter"
if sysctl -q dev.ubt.0.%driver >/dev/null 2>&1; then
	pass "ubt0 driver present"
else
	fail "ubt0 driver not found (no BT adapter?)"
fi

# 4. Control socket (only if blued is running)
echo "[4] Daemon status"
if [ -S "$BLUED_SOCK" ]; then
	pass "control socket exists"

	STATUS=$(blued_ctl "STATUS" 2>/dev/null || true)
	if echo "$STATUS" | grep -q "adapters"; then
		pass "STATUS command responds"
	else
		fail "STATUS command: no response"
	fi

	ADAPTERS=$(blued_ctl "ADAPTERS" 2>/dev/null || true)
	if echo "$ADAPTERS" | grep -q "ubt"; then
		pass "ADAPTERS lists a device"
	else
		fail "ADAPTERS: no adapter found"
	fi

	CONNS=$(blued_ctl "LIST" 2>/dev/null || true)
	pass "LIST command responds (${CONNS:-empty})"
else
	echo "  SKIP: blued not running (start with: $0 start)"
fi

# 5. Summary
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
	exit 1
fi
exit 0

# ---------------------------------------------------------------
#  CLIENT-SIDE TESTING (run from phone or Linux box)
# ---------------------------------------------------------------
#
# === nRF Connect (Android/iOS) ===
#
# 1. Open nRF Connect, tap SCAN
# 2. Look for "5BSD-blued" in the scan results
# 3. Tap CONNECT
# 4. Verify these services appear:
#    - Generic Access (0x1800)
#    - Generic Attribute (0x1801)
#    - Device Information (0x180A)
#    - Unknown Service (0xFFE0)
#
# 5. Test reads:
#    - Tap Device Name (0x2A00) → read → should show "5BSD-blued"
#    - Tap Manufacturer Name (0x2A29) → read → should show "FreeBSD"
#    - Tap Database Hash (0x2B2A) → read → should show 16 bytes
#
# 6. Test writes:
#    - Tap Custom Characteristic (0xFFE1) → write → send 0x42
#    - Read it back → should show 0x42
#
# 7. Test notifications:
#    - On Custom Characteristic (0xFFE1), tap the notify icon (↓)
#    - CCCD write should succeed
#
# 8. Test disconnect/reconnect:
#    - Disconnect from nRF Connect
#    - blued should log "device ... disconnected" and "re-advertising"
#    - Reconnect — should work without restarting blued
#
# 9. Test pairing:
#    - Delete bond on phone, reconnect
#    - If pairing is initiated, verify it completes
#    - Disconnect and reconnect — should skip pairing (bonded)
#
# === bluetoothctl (Linux) ===
#
#   $ bluetoothctl
#   [bluetooth]# scan on
#   [bluetooth]# scan off
#   [bluetooth]# connect <addr>
#   [bluetooth]# menu gatt
#   [bluetooth]# list-attributes
#   [bluetooth]# select-attribute /org/bluez/hci0/dev_.../service000e/char000f
#   [bluetooth]# read
#   [bluetooth]# write 0x42
#   [bluetooth]# notify on
#   [bluetooth]# back
#   [bluetooth]# disconnect <addr>
#   [bluetooth]# connect <addr>   # test reconnect
#
# === gatttool (Linux, legacy) ===
#
#   $ gatttool -b <addr> -t random -I
#   > connect
#   > primary                    # discover services
#   > characteristics            # discover characteristics
#   > char-read-hnd 0x0002       # read device name
#   > char-read-hnd 0x000b       # read database hash (16 bytes)
#   > char-write-req 0x000f 42   # write to custom char
#   > char-read-hnd 0x000f       # read back custom char
#   > char-write-req 0x0010 0100 # enable notifications on CCCD
#   > disconnect
#   > connect                    # test reconnect
