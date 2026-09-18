#!/bin/sh
# Install/remove THROUGH pkg(8): ship pkg-static + a real .pkg of a bundle into
# the image; on the VM `pkg add` it (no reload) -> the watch loads the unit and
# its container appears; `pkg delete` -> the watch unloads it; reboot -> reaped.
TOP=$(cd "$(dirname "$0")/.." && pwd); . "$TOP/lib/vmlib.sh"
scrub_stage
echo "==> stage pkg-static + pkgtest-1.0.0.pkg into /root; ensure Apps/ exists in the image"
chmod u+w "$R/METALOG"; grep -vE 'Capabilities/System/(Test|A|B|C)\.cap|^\./root/pkg-static |^\./root/pkgtest-1.0.0.pkg |^\./Capabilities/Apps ' "$R/METALOG" > "$R/METALOG.new" && mv "$R/METALOG.new" "$R/METALOG"
for n in Test A B C; do chmod -R u+w $R/Capabilities/System/$n.cap 2>/dev/null; rm -rf $R/Capabilities/System/$n.cap; done
# Build the test package here: the bundle skeleton is in pkgbuild/, the unit
# binary is the reclaimprobe just built; pkg-static (a static host binary)
# both creates the package and, shipped to the guest, installs it.
PKG=${PKG_STATIC:-/usr/local/sbin/pkg-static}
cp "$PROBES/reclaimprobe" "$TOP/pkgbuild/root/Capabilities/Apps/Pkgtest.cap/Units/reclaimprobe.unit/bin/reclaimprobe"; chmod 0555 "$TOP/pkgbuild/root/Capabilities/Apps/Pkgtest.cap/Units/reclaimprobe.unit/bin/reclaimprobe"
(cd "$TOP/pkgbuild" && "$PKG" create -M MANIFEST -p plist -r root -o "$WORK") || { echo "pkg create failed"; exit 2; }
rm -f $R/root/pkg-static; cp "$PKG" $R/root/pkg-static; chmod 0555 $R/root/pkg-static; rm -f $R/root/pkgtest-1.0.0.pkg; cp "$WORK/pkgtest-1.0.0.pkg" $R/root/; mkdir -p $R/Capabilities/Apps
cat >> "$R/METALOG" <<EOF
./root/pkg-static type=file uname=root gname=wheel mode=0555
./root/pkgtest-1.0.0.pkg type=file uname=root gname=wheel mode=0644
./Capabilities/Apps type=dir uname=root gname=wheel mode=0755
EOF
echo "==> build image"; build_image pk
echo "==> boot #1: pkg add (no reload)"
boot rw || exit 1
V "/root/pkg-static add /root/pkgtest-1.0.0.pkg 2>&1 | tail -3; echo PKG_ADD_RC=\$?" 60
V "sleep 8; /root/pkg-static info pkgtest 2>&1 | head -3; ls /Capabilities/Apps/Pkgtest.cap 2>&1 | tr '\n' ' '; echo" 20
V "grep -a 'registry:' /var/log/messages | tail -3" 12
V "ps ax -o command | grep -c '[r]eclaimprobe' | sed 's/^/PROBE_UP=/'; ls /Capabilities/Run/live | grep -c '^Pkgtest\$' | sed 's/^/RUNLIVE=/'; sleep 12; zfs list zroot/Capabilities/Data/Pkgtest/reclaimprobe/persistent/state >/dev/null 2>&1 && echo PKG_INSTALL_CLAIMED_PASS || echo PKG_INSTALL_NO_CLAIM_FAIL; grep -a 'reclaimprobe' /var/log/messages | tail -2" 40
echo "==> pkg delete (no reload)"
V "/root/pkg-static delete -y pkgtest 2>&1 | tail -2; sleep 8; [ -e /Capabilities/Apps/Pkgtest.cap ] && echo PKG_DELETE_DIR_LEFT_FAIL || echo PKG_DELETE_DIR_GONE_PASS" 60
V "grep -a 'registry:' /var/log/messages | tail -3; n=\$(ps ax -o command | grep -c '[r]eclaimprobe'); echo PROBE_UP_AFTER_DELETE=\$n; [ \"\$n\" = 0 ] && echo PKG_DELETE_UNLOADED_PASS || echo PKG_DELETE_STILL_RUNNING_FAIL; ls /Capabilities/Run/live | grep -c '^Pkgtest\$' | sed 's/^/RUNLIVE_AFTER_DELETE=/'; sync; sync; sleep 8" 40
echo "==> boot #2: reap"
boot rw || exit 1
V "grep -a 'reclaim:' /var/log/messages | tail -3" 12
echo "=== verdicts ==="
V "zfs list zroot/Capabilities/Data/Pkgtest >/dev/null 2>&1 && echo PKG_CONTAINER_PRESENT_FAIL || echo PKG_CONTAINER_REAPED_PASS" 15
echo DONE
