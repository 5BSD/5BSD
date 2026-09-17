#!/bin/sh
# Scale: twelve bundles installed in ONE burst into Apps/, then removed in one
# burst.  The watch must settle the burst into one load, every unit must run
# and claim, every marker and container must appear; the removal must unload
# all twelve; the next boot reaps all twelve containers in one pass.
TOP=$(cd "$(dirname "$0")/.." && pwd); . "$TOP/lib/vmlib.sh"
echo "==> stage /root/burst/B01..B12.cap (reclaimprobe each)"
scrub_stage
rm -rf "$R/root/burst"; mkdir -p "$R/root/burst"
grep -v "^\./root/burst" "$R/METALOG" > "$R/METALOG.new" && mv "$R/METALOG.new" "$R/METALOG"
echo "./root/burst type=dir uname=root gname=wheel mode=0755" >> "$R/METALOG"
for i in 01 02 03 04 05 06 07 08 09 10 11 12; do
	d=$(stage_bundle Apps B$i app.B$i "" reclaimprobe reclaimprobe); mv "$d" "$R/root/burst/B$i.cap"
	grep -v "Capabilities/Apps/B$i.cap" "$R/METALOG" > "$R/METALOG.new" && mv "$R/METALOG.new" "$R/METALOG"; meta_bundle ./root/burst/B$i.cap reclaimprobe >> "$R/METALOG"
done
build_image burst
boot rw || exit 1
V "mkdir -p /Capabilities/Apps; date +%T; cp -Rp /root/burst/B*.cap /Capabilities/Apps/; i=0; while [ \$(pgrep -f '[/ ]reclaimprobe( |\$)' | wc -l) -lt 12 ] && [ \$i -lt 120 ]; do i=\$((i+1)); sleep 0.5; done; date +%T; echo LOAD_WAIT_HALFSECS=\$i; pgrep -f '[/ ]reclaimprobe( |\$)' | wc -l | tr -d ' ' | sed 's/^/UNITS_UP=/'; ls /Capabilities/Run/live | grep -c '^B[0-9][0-9]\$' | sed 's/^/MARKERS=/'; grep -ac 'install folders changed; reloading' /var/log/messages | sed 's/^/RELOADS=/'" 90
V "sleep 6; zfs list -H -o name -r zroot/Capabilities/Data | grep -c '^zroot/Capabilities/Data/B[0-9][0-9]/reclaimprobe/persistent/state\$' | sed 's/^/CONTAINERS=/'" 30
V "[ \$(pgrep -f '[/ ]reclaimprobe( |\$)' | wc -l) = 12 ] && echo BURST_ALL_UP_PASS || echo BURST_UNITS_FAIL; [ \$(ls /Capabilities/Run/live | grep -c '^B[0-9][0-9]\$') = 12 ] && echo BURST_MARKERS_PASS || echo BURST_MARKERS_FAIL; [ \$(zfs list -H -o name -r zroot/Capabilities/Data | grep -c '^zroot/Capabilities/Data/B[0-9][0-9]/reclaimprobe/persistent/state\$') = 12 ] && echo BURST_CONTAINERS_PASS || echo BURST_CONTAINERS_FAIL; grep -aq 'quarantined' /var/log/messages && echo BURST_QUARANTINE_SEEN || true" 30
echo "==> remove all twelve in one burst"
V "chmod -R u+w /Capabilities/Apps/B*.cap; rm -rf /Capabilities/Apps/B*.cap; i=0; while [ \$(pgrep -f '[/ ]reclaimprobe( |\$)' | wc -l) -gt 0 ] && [ \$i -lt 120 ]; do i=\$((i+1)); sleep 0.5; done; echo UNLOAD_WAIT_HALFSECS=\$i; pgrep -f '[/ ]reclaimprobe( |\$)' | wc -l | tr -d ' ' | sed 's/^/UNITS_AFTER_RM=/'; sleep 2; ls /Capabilities/Run/live | grep -c '^B[0-9][0-9]\$' | sed 's/^/MARKERS_AFTER_RM=/'; [ \$(pgrep -f '[/ ]reclaimprobe( |\$)' | wc -l) = 0 ] && [ \$(ls /Capabilities/Run/live | grep -c '^B[0-9][0-9]\$') = 0 ] && echo BURST_UNLOAD_PASS || echo BURST_UNLOAD_FAIL; sync; sync; sleep 8" 120
boot rw || exit 1
V "sleep 3; grep -a 'reclaim:' /var/log/messages | tail -2 | cut -c1-160; n=\$(zfs list -H -o name -r zroot/Capabilities/Data | grep -c '^zroot/Capabilities/Data/B[0-9][0-9]\$'); echo CONTAINERS_LEFT=\$n; [ \$n = 0 ] && grep -aq 'boot pass reaped 12 orphans' /var/log/messages && echo BURST_REAPED_ALL_PASS || echo BURST_REAP_FAIL" 30
echo DONE
