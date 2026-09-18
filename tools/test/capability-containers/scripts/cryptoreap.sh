#!/bin/sh
# localcrypto container-model key reap, end to end: Test.cap/cryptoprobe mints a
# NAMED key under bundle "Test" in the kernel keystore; remove the bundle (the
# watch unloads it); on the next boot localcrypto's reconcile must drop the key.
# Observed with /root/keyowners (kernel owner list) on both boots.
TOP=$(cd "$(dirname "$0")/.." && pwd); . "$TOP/lib/vmlib.sh"
scrub_stage
echo "==> stage Test.cap (cryptoprobe) + /root/keyowners"
TC=$R/Capabilities/System/Test.cap
chmod -R u+w "$TC" 2>/dev/null; rm -rf "$TC"
mkdir -p "$TC/Units/cryptoprobe.unit/bin"; cp "$PROBES/cryptoprobe" "$TC/Units/cryptoprobe.unit/bin/cryptoprobe"; chmod 0555 "$TC/Units/cryptoprobe.unit/bin/cryptoprobe"
printf 'activation { boot = true; }\nprogram = "cryptoprobe";\nrestart = "never";\nuser = "root";\n' > "$TC/Units/cryptoprobe.unit/Unit.ucl"
cat > "$TC/Bundle.ucl" <<-'EOF'
	schema = "org.5bsd.capability-bundle";
	schema_version = 1;
	bundle_id = "app.Test";
	version = "1.0.0";
	sequence = 1;
	author = "5BSD";
	publisher = "org.5bsd.base";
	units = ["cryptoprobe"];
	EOF
rm -f "$R/root/keyowners"; cp "$PROBES/keyowners" "$R/root/keyowners"; chmod 0555 "$R/root/keyowners"
chmod u+w "$R/METALOG"; grep -v 'Capabilities/System/Test.cap\|^\./root/keyowners ' "$R/METALOG" > "$R/METALOG.new" && mv "$R/METALOG.new" "$R/METALOG"
cat >> "$R/METALOG" <<EOF
./Capabilities/System/Test.cap type=dir uname=root gname=wheel mode=0755
./Capabilities/System/Test.cap/Bundle.ucl type=file uname=root gname=wheel mode=0644
./Capabilities/System/Test.cap/Units type=dir uname=root gname=wheel mode=0755
./Capabilities/System/Test.cap/Units/cryptoprobe.unit type=dir uname=root gname=wheel mode=0755
./Capabilities/System/Test.cap/Units/cryptoprobe.unit/Unit.ucl type=file uname=root gname=wheel mode=0644
./Capabilities/System/Test.cap/Units/cryptoprobe.unit/bin type=dir uname=root gname=wheel mode=0755
./Capabilities/System/Test.cap/Units/cryptoprobe.unit/bin/cryptoprobe type=file uname=root gname=wheel mode=0555
./root/keyowners type=file uname=root gname=wheel mode=0555
EOF
echo "==> build image"
build_image cr
echo "==> boot #1: cryptoprobe mints a named key under bundle Test"
boot rw || exit 1
V "sleep 3; ps ax -o command | grep cryptoprobe | grep -v grep | wc -l | tr -d ' ' | sed 's/^/PROBE_UP=/'; /root/keyowners" 20
V "grep -a 'cryptoprobe' /var/log/messages | tail -2" 12
echo "==> remove the bundle (watch unloads), settle, restart"
V "chmod -R u+w /Capabilities/System/Test.cap; rm -rf /Capabilities/System/Test.cap; sleep 6; ps ax -o command | grep cryptoprobe | grep -v grep | wc -l | tr -d ' ' | sed 's/^/PROBE_UP_AFTER_RM=/'; /root/keyowners; sync; sync; sleep 8" 40
echo "==> boot #2: localcrypto BOOT reconcile drops Test's keys"
boot rw || exit 1
V "sleep 5; /root/keyowners" 20
V "grep -aE 'reclaim' /var/log/messages | grep -viE 'tzfsd' | tail -3" 12
echo "=== verdicts ==="
V "if /root/keyowners | grep -q '^OWNER=Test\$'; then echo CRYPTO_KEY_STILL_HELD_FAIL; else echo CRYPTO_KEY_REAPED_PASS; fi" 20
echo DONE
