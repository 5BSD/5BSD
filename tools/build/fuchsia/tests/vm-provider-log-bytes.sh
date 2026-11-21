#!/bin/sh
# The host reads the serial log byte for byte: syslogd's vis(3) encoding can
# leave a lone UTF-8 lead byte in it (an em dash in a message), and tr(1)
# under a UTF-8 locale then fails ("Illegal byte sequence"), which made a
# clean run VM_NOT_CLEAN.  Every host read of the log runs tr in the C
# locale.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
bad=$(grep -n "tr -d '\\\\r' < \"\\\$log\"" "$root/vm-provider.sh" | grep -v "LC_ALL=C tr -d" || true)
[ -z "$bad" ] || { echo "FAIL: host log reads outside the C locale:"; echo "$bad"; exit 1; }
printf 'KYUA_VM_DONE\r\nfailed \342M-^@M-^T aborting\r\n' > "$work/log"
log=$work/log
[ "$(LC_ALL=C.UTF-8 sh -c "LC_ALL=C tr -d '\\r' < \"\$0\" | grep -acx KYUA_VM_DONE" "$log")" = 1 ] ||
    { echo "FAIL: a lone lead byte stops the log read"; exit 1; }
echo 'PASS the host reads the serial log in the C locale'
