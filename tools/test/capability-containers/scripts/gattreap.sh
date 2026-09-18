#!/bin/sh
# Container-model proof: blued as a reconcile client.  Units open the daemon
# over the capability plane (ble_open_plane: their stamped identity reaches
# blued) and register local GATT services; blued attributes each service's
# handle range to the unit's bundle in a sidecar beside its persisted GATT
# artifact and reconciles the records against the installed bundles on a
# timer: an uninstalled bundle's services are removed, the others stay; a
# service registered over the socket path (no identity) is never reaped;
# a restart restores the services with their records; a bundle removed
# while the daemon was down is reaped by the boot pass once it runs.
#
#   G1 (boot): service 0xfff0      G2 (boot): service 0xffe4
#   G3 (boot): service 0xffd0 -- stays installed: it re-activates blued at
#                                 every boot (the daemon is on-demand)
#
# A VM has no Bluetooth adapter and blued exits without one: the probes have
# sysextd load the netgraph stack and the virtual HCI (the shipped allow-list
# is replaced for the run), and the proof creates a virtual controller with
# vhcitool(8) after each login (it stays running: it IS the emulated
# controller, serving the /dev/vhciN packet pipe), inside the delay the
# probes wait before their first open.  blued's timer/grace is shortened to 15s through its
# unit environment; the METALOG size fields of the edited files are dropped
# (makefs truncates to the spec size).  blued's state store is
# anonymous-mounted: its artifacts are read through a snapshot/clone with
# the gattowners probe.
TOP=$(cd "$(dirname "$0")/.." && pwd); . "$TOP/lib/vmlib.sh"
scrub_stage
BU=$R/Capabilities/System/Bluetooth.cap/Units/blued.unit/Unit.ucl
SC=$R/Capabilities/Config/sysextd.ucl
rm -f "$WORK/blued.Unit.ucl.orig" "$WORK/sysextd.conf.orig"
cp "$BU" "$WORK/blued.Unit.ucl.orig"; cp "$SC" "$WORK/sysextd.conf.orig"
trap 'chmod u+w "$BU" "$SC"; cp "$WORK/blued.Unit.ucl.orig" "$BU"; cp "$WORK/sysextd.conf.orig" "$SC"' EXIT
chmod u+w "$BU" "$SC" "$R/METALOG"
grep -q '^environment' "$BU" || printf 'environment { BLUED_RECLAIM_INTERVAL = "15"; }\n' >> "$BU"
sed -i '' 's#^\(\./Capabilities/System/Bluetooth.cap/Units/blued.unit/Unit.ucl type=file.*\) size=[0-9]*#\1#' "$R/METALOG"
cat > "$SC" <<'EOF'
# gattreap proof: the shipped set plus the Bluetooth netgraph stack and the
# virtual HCI the probes need on an adapter-less VM.
allowed_extensions = ["cryptodev", "vhid", "zfs", "linux64",
    "ng_socket", "ng_bluetooth", "ng_hci", "ng_l2cap", "ng_btsocket",
    "ng_hci_virt"];
EOF
sed -i '' 's#^\(\./Capabilities/Config/sysextd.ucl type=file.*\) size=[0-9]*#\1#' "$R/METALOG"
# gattowners reads the daemon's artifacts from the shell.
mkdir -p "$R/root"; cp "$PROBES/gattowners" "$R/root/gattowners"; chmod 0555 "$R/root/gattowners"
grep -q '^\./root/gattowners ' "$R/METALOG" || echo "./root/gattowners type=file uname=root gname=wheel mode=0555" >> "$R/METALOG"

echo "==> stage G1, G2, G3 (gattprobe each)"
stage_bundle System G1 app.G1 "" gattprobe gattprobe 'protect = [];' 'arguments = ["fff0", "100"];' >/dev/null
stage_bundle System G2 app.G2 "" gattprobe gattprobe 'protect = [];' 'arguments = ["ffe4", "100"];' >/dev/null
stage_bundle System G3 app.G3 "" gattprobe gattprobe 'protect = [];' 'arguments = ["ffd0", "100"];' >/dev/null
build_image gr
boot rw || exit 1
BD=zroot/Capabilities/Data/Bluetooth/blued/persistent/state
D1=zroot/Capabilities/Data/G1/gattprobe/persistent/state
D2=zroot/Capabilities/Data/G2/gattprobe/persistent/state
D3=zroot/Capabilities/Data/G3/gattprobe/persistent/state
# The daemon's artifacts, through a snapshot/clone: OWNER/SERVICE lines.
ART="zfs destroy -r zroot/obsclone 2>/dev/null; zfs destroy $BD@obs 2>/dev/null; zfs snapshot $BD@obs && zfs clone -o mountpoint=/mnt/obs $BD@obs zroot/obsclone && /root/gattowners /mnt/obs; zfs destroy -r zroot/obsclone 2>/dev/null; zfs destroy $BD@obs 2>/dev/null"

echo "=== a virtual controller for the daemon (the probes load the stack, then wait) ==="
V "sleep 15; kldstat | grep -c 'ng_' | sed 's/^/NG_MODULES=/'; nohup vhcitool -n 1 -L > /var/log/vhcitool.log 2>&1 & sleep 4; head -3 /var/log/vhcitool.log; ngctl list 2>/dev/null | grep -c vhci | sed 's/^/VHCI_NODES=/'; pgrep -c vhcitool | sed 's/^/EMULATORS=/'" 60
echo "=== the three units registered over the plane; the sidecar attributes each service ==="
V "sleep 100; ps ax | grep -c '[B]luetooth (blued)' | sed 's/^/BLUED_PROCS=/'; for d in $D1 $D2 $D3; do $(OBS \$d) >/dev/null 2>&1; cat /mnt/obs/result; done; $(DROP_OBS $D3); echo '--- artifacts:'; $ART" 200
V "A=\$($ART); echo \"\$A\" | grep -q '^OWNER .* fff0 G1\$' && echo \"\$A\" | grep -q '^OWNER .* ffe4 G2\$' && echo \"\$A\" | grep -q '^OWNER .* ffd0 G3\$' && echo GATT_ATTRIBUTED_PASS || echo GATT_ATTRIBUTION_FAIL; echo \"\$A\" | grep -q '^SERVICE .* fff0\$' && echo \"\$A\" | grep -q '^SERVICE .* ffe4\$' && echo GATT_PERSISTED_PASS || echo GATT_PERSIST_FAIL" 60

echo "=== a socket-path client (root, no identity) registers 0xfff9: unattributed ==="
V "bluedctl add-service fff9 2>&1 | tail -1; sleep 2; A=\$($ART); echo \"\$A\" | grep -q '^SERVICE .* fff9\$' && ! echo \"\$A\" | grep -q '^OWNER .* fff9 ' && echo SOCKET_CLIENT_UNATTRIBUTED_PASS || echo SOCKET_CLIENT_ATTRIBUTION_FAIL" 60

echo "=== G1 uninstalled: its service goes on the timer pass; G2's, G3's and the socket client's stay ==="
V "chmod -R u+w /Capabilities/System/G1.cap; rm -rf /Capabilities/System/G1.cap; sleep 50; grep -a 'blued.*reclaim' /var/log/messages | tail -3 | cut -c1-170; echo '--- artifacts:'; $ART" 90
V "A=\$($ART); echo \"\$A\" | grep -q ' fff0' && echo G1_SERVICE_STILL_THERE_FAIL || echo G1_SERVICE_REAPED_PASS; echo \"\$A\" | grep -q '^OWNER .* ffe4 G2\$' && echo \"\$A\" | grep -q '^SERVICE .* ffe4\$' && echo G2_SERVICE_KEPT_PASS || echo G2_SERVICE_LOST_FAIL; echo \"\$A\" | grep -q '^SERVICE .* fff9\$' && echo SOCKET_SERVICE_KEPT_PASS || echo SOCKET_SERVICE_LOST_FAIL" 60

echo "=== G2's unit dies but its bundle stays: the service outlives the connection ==="
V "pkill -f '[/ ]gattprobe ffe4'; sleep 40; A=\$($ART); echo \"\$A\" | grep -q '^OWNER .* ffe4 G2\$' && echo \"\$A\" | grep -q '^SERVICE .* ffe4\$' && echo CONNECTION_LOSS_KEEPS_SERVICE_PASS || echo CONNECTION_LOSS_LOST_SERVICE_FAIL" 60

echo "=== G2 uninstalled while the daemon is stopped, then reboot: the boot pass reaps it once G3 re-activates blued ==="
V "chmod -R u+w /Capabilities/System/G2.cap; rm -rf /Capabilities/System/G2.cap; sync; sync; sleep 3" 20
boot rw || exit 1
V "sleep 15; nohup vhcitool -n 1 -L > /var/log/vhcitool.log 2>&1 & sleep 110; ps ax | grep -c '[B]luetooth (blued)' | sed 's/^/BLUED_PROCS=/'; grep -a 'blued.*reclaim' /var/log/messages | tail -3 | cut -c1-170; echo '--- artifacts:'; $ART" 180
V "A=\$($ART); echo \"\$A\" | grep -q '^OWNER .* ffd0 G3\$' && echo \"\$A\" | grep -q '^SERVICE .* ffd0\$' && echo RESTART_RESTORES_G3_PASS || echo RESTART_LOST_G3_FAIL; echo \"\$A\" | grep -q ' ffe4' && echo G2_NOT_REAPED_AT_BOOT_FAIL || echo G2_REAPED_AT_BOOT_PASS; echo \"\$A\" | grep -q '^SERVICE .* fff9\$' && echo SOCKET_SERVICE_SURVIVES_REBOOT_PASS || echo SOCKET_SERVICE_LOST_ON_REBOOT_FAIL" 60
echo DONE
