#!/bin/sh
# Reproduce the first-boot ZFS sync panic (VERIFY3U(dr->dr_dbuf->db_level,
# ==, level)) and capture its dump: on a FRESH image each round, three
# stressprobe units hammer claims/writes/destroys through bsdfilesystem while a shell
# loop creates, fills, snapshots and destroys datasets.  A panic dumps and
# reboots (debugger_on_panic=0); the dump is then read in-guest with lldb.
#   ROUNDS (default 12), STRESS_SECS per round (default 150)
TOP=$(cd "$(dirname "$0")/.." && pwd); . "$TOP/lib/vmlib.sh"
: "${ROUNDS:=12}"; : "${STRESS_SECS:=150}"
echo "==> stage S1..S3 (stressprobe each)"
scrub_stage
grep -vE 'Capabilities/System/S[123]\.cap' "$R/METALOG" > "$R/METALOG.new" && mv "$R/METALOG.new" "$R/METALOG"
for n in S1 S2 S3; do chmod -R u+w "$R/Capabilities/System/$n.cap" 2>/dev/null; rm -rf "$R/Capabilities/System/$n.cap"; done
for n in 1 2 3; do d=$(stage_bundle System S$n app.S$n "" stressprobe stressprobe); sed -i '' 's/restart = "never";/restart = "always";/' "$d/Units/stressprobe.unit/Unit.ucl"; done
GUEST_LOOP='nohup sh -c "i=0; while :; do i=\$((i+1)); d=zroot/scratch\$((i%8)); zfs create -o refquota=64m \$d 2>/dev/null; m=\$(zfs get -H -o value mountpoint \$d); dd if=/dev/zero of=\$m/f bs=128k count=\$((i%40+1)) 2>/dev/null; sync; zfs snapshot \$d@s 2>/dev/null; zfs destroy -r \$d 2>/dev/null; done" >/dev/null 2>&1 &'
r=0
while [ $r -lt $ROUNDS ]; do
	r=$((r+1)); echo "==> round $r: fresh image, first boot ($(date +%H:%M:%S))"
	build_image zs
	boot rw || { echo "ROUND $r: PANIC DURING BOOT (dump handled by boot())"; exit 0; }
	V "pgrep -fc '[/ ]stressprobe( |\$)' | sed 's/^/STRESSERS=/'; $GUEST_LOOP; echo loop started" 20
	t=0; panicked=0
	while [ $t -lt $STRESS_SECS ]; do
		sleep 15; t=$((t+15))
		if tr -d '\r' < "$CONS" | grep -qE "^panic: "; then panicked=1; break; fi
	done
	if [ $panicked = 1 ]; then
		echo "ROUND $r: PANIC at ~${t}s"; tr -d '\r' < "$CONS" | grep -a -A14 "^panic: " | head -18
		# wait for the automatic reboot's login prompt
		i=0; while [ $i -lt 80 ]; do sleep 3; [ $(tr -d '\r' < "$CONS" | grep -c "login:") -ge 2 ] && break; i=$((i+1)); done
		sleep 8; printf '\r' >> "$CBUF"; sleep 2
		echo "--- crash dump:"
		V "ls -la /var/crash | tail -4; head -14 /var/crash/info.0 2>/dev/null" 40
		V "cd /var/crash && lldb --batch -o 'bt' -c vmcore.0 /boot/kernel/kernel 2>&1 | grep -E 'frame #|error|warning' | head -40" 400
		V "cd /var/crash && lldb --batch -o 'bt' -c vmcore.0 /boot/kernel/kernel 2>&1 | grep -n 'dbuf_sync_list' | head -2" 300
		V "cd /var/crash && F=\$(lldb --batch -o 'bt' -c vmcore.0 /boot/kernel/kernel 2>&1 | grep -E 'frame #[0-9]+:.*dbuf_sync_list' | head -1 | sed 's/.*frame #\([0-9]*\).*/\1/'); echo FRAME=\$F; lldb --batch -o \"frame select \$F\" -o 'frame variable' -o 'p level' -o 'p dr->dr_dbuf->db_level' -o 'p dr->dr_dbuf->db_blkid' -o 'p dr->dr_dbuf->db.db_object' -o 'p dr->dr_txg' -o 'up' -o 'p dn->dn_object' -o 'p dn->dn_nlevels' -o 'p dn->dn_type' -o 'p dn->dn_objset->os_dsl_dataset->ds_dir->dd_myname' -c vmcore.0 /boot/kernel/kernel 2>&1 | grep -v '^\$' | head -60" 500
		pkill -9 -f qemu-system-x86_64 2>/dev/null; sleep 2
		keep="$VM/panic-stress-$(date +%Y%m%d-%H%M%S).img"; cp "$VM/bsd-guest.img" "$keep" && echo "image preserved: $keep"
		echo "REPRODUCED in round $r"; exit 0
	fi
	V "pgrep -fc '[/ ]stressprobe( |\$)' | sed 's/^/STRESSERS_ALIVE=/'; zfs list -H -o name -r zroot/Capabilities/Data | grep -c '/cache/' | sed 's/^/CACHE_DATASETS=/'; mount | grep -c anon | sed 's/^/ANON_MOUNTS=/'; D=zroot/Capabilities/Data/S1/stressprobe/persistent/state; zfs destroy -r zroot/obsclone 2>/dev/null; zfs destroy \$D@obs 2>/dev/null; zfs snapshot \$D@obs && zfs clone -o mountpoint=/mnt/obs \$D@obs zroot/obsclone && tail -4 /mnt/obs/result; zfs destroy -r zroot/obsclone; zfs destroy \$D@obs" 40
	echo "ROUND $r: no panic in ${STRESS_SECS}s"
done
echo "NOT REPRODUCED in $ROUNDS rounds"
