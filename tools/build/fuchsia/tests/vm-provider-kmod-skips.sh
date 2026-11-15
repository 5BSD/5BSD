#!/bin/sh
# vm-provider.sh: a case kyua skipped because a required kernel module was
# not loaded makes the run VM_NOT_CLEAN.  Runs the actual block of
# vm-provider.sh; no guest.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

sed -n '/^nkmod=/,/^fi$/p' "$root/vm-provider.sh" > "$work/kmod.sh"
grep -q 'Required kmods are not loaded' "$work/kmod.sh"
log=$work/serial.log
run() {
	log=$log sh -c "verdict=VM_CLEAN; . '$work/kmod.sh'; echo \$verdict"
}
cat > "$log" <<'EOS'
KYUA_SKIPPED_LIST_BEGIN
sys/a:one  ->  skipped: Required kmods are not loaded: mac_test_hooks.  [0.1s]
sys/a:two  ->  skipped: something else  [0.1s]
KYUA_SKIPPED_LIST_END
EOS
out=$(run)
echo "$out" | grep -q '^KMOD_SKIPPED=1 '
echo "$out" | tail -n 1 | grep -qx VM_NOT_CLEAN
cat > "$log" <<'EOS'
KYUA_SKIPPED_LIST_BEGIN
sys/a:two  ->  skipped: something else  [0.1s]
KYUA_SKIPPED_LIST_END
EOS
out=$(run)
[ "$out" = VM_CLEAN ] || { echo "FAIL: unrelated skip changed the verdict"; exit 1; }

echo 'PASS required-kmod skips make the run not clean'
