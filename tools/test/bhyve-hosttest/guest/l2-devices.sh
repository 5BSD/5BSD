#!/bin/sh
# L2 only. Fixed test topology: vtbd0 boot; slots 5/6/7 scratch disks.
set -u
stage=${1:?before or after}
case "$stage" in before|after) ;; *) exit 2 ;; esac
[ "$(kenv -q hosttest.role)" = l2 ] &&
 [ "$(kenv -q hosttest.l2devices)" = storage ] || exit 2
S=${L2_DEVICE_WORKDIR:-/tmp/l2-device-check}
mkdir -p "$S" || exit 1
T=${SRTOOL:-/root/hosttest/srtool}
failed=0
mount -p > "$S/mounts" || { echo "L2-DEVICE FAIL cannot-read-mounts"; exit 1; }
pciconf -l | sed 's/^/L2-PCI /'
for kind in virtio-blk nvme ahci; do
 case "$kind" in
 virtio-blk) dev=vtbd1; seed=711 ;;
 nvme) dev=nda0; [ -c /dev/$dev ] || dev=nvd0; seed=712 ;;
 ahci) dev=ada0; seed=713 ;;
 esac
 ok=yes
 # Refuse any unexpected capacity or a mounted target, including partitions.
 bytes=$(diskinfo /dev/$dev 2>/dev/null | awk '{print $3}')
 if [ "$bytes" != 16777216 ] || awk -v d="/dev/$dev" 'index($1,d)==1 {found=1} END {exit !found}' "$S/mounts"; then
  echo "L2-DEVICE $kind $stage FAIL unsafe-or-absent dev=$dev bytes=$bytes"; failed=1; continue
 fi
 if [ "$stage" = after ]; then
  "$T" expect 4 "$seed" > "$S/want" || ok=no
  dd if=/dev/$dev of="$S/read" bs=1m count=4 > "$S/dd.log" 2>&1 || ok=no
  [ "$(sha256 -q "$S/read")" = "$(cat "$S/want")" ] || ok=no
  seed=$((seed + 100))
 fi
 "$T" pattern 4 "$seed" > "$S/pattern" || ok=no
 if [ "$ok" = yes ]; then
  dd if="$S/pattern" of=/dev/$dev bs=1m > "$S/dd.log" 2>&1 || ok=no
  sync
  dd if=/dev/$dev of="$S/read" bs=1m count=4 >> "$S/dd.log" 2>&1 || ok=no
  cmp -s "$S/pattern" "$S/read" || ok=no
 fi
 if [ "$ok" = yes ]; then
  echo "L2-DEVICE $kind $stage PASS dev=$dev seed=$seed"
 else
  echo "L2-DEVICE $kind $stage FAIL dev=$dev"; cat "$S/dd.log"; failed=1
 fi
done
exit "$failed"
