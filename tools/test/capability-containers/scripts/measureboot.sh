#!/bin/sh
# Boot-time measurement for the capability plane (native-launch / /etc/rc overlap).
#
# Stages reclaimprobe as a boot unit (it claims storage from the native
# BSDFilesystem provider and writes a marker the instant it is served).  The key
# metric is measured INSIDE the guest, immune to console/harness timing:
#   SERVE_S = marker mtime - kern.boottime
#           = seconds from kernel boot until BSDFilesystem first served a native
#             boot unit -- i.e. time until the capability plane is USABLE, which
#             is exactly what launching native units in parallel with /etc/rc is
#             meant to shorten.
# LOGIN is vmlib's coarse "~Ns" wall proxy (30s harness offset; reported for
# context only).  Runs each switchboard variant REPS times; min SERVE_S wins.
TOP=$(cd "$(dirname "$0")/.." && pwd); . "$TOP/lib/vmlib.sh"
: "${REPS:=2}"
: "${SB_OVERLAP:?set SB_OVERLAP to the overlap switchboard binary}"
: "${SB_SERIAL:?set SB_SERIAL to the serial-baseline switchboard binary}"
MARK=zroot/Capabilities/Data/Test/boottimeprobe/persistent/state

stage_switchboard() {
	local bin=$1 p=/usr/libexec/switchboard
	chmod u+w "$R$p"; cp "$bin" "$R$p"; chmod 0555 "$R$p"
	chmod u+w "$R/METALOG"
	sed -i '' "s#^\(\./usr/libexec/switchboard type=file [^ ]* [^ ]* mode=[0-7]*\) size=[0-9]*#\1#" "$R/METALOG"
}

# After boot() has left the guest at a login prompt, read the in-guest timing.
measure_serve() {
	sh "$RIG/vcmd.sh" "k=0; while [ \$k -lt 20 ]; do zfs list $MARK >/dev/null 2>&1 && break; sleep 2; k=\$((k+1)); done; \
	   $(OBS $MARK); v=\$(cat /mnt/obs/servetime 2>/dev/null); $(DROP_OBS $MARK); \
	   [ -n \"\$v\" ] && echo SERVE_S=\$v || echo SERVE_S=NA" 70
}

run_variant() {
	local name=$1 bin=$2 rep best=9999 out lg sv
	stage_switchboard "$bin"
	build_image mb
	rep=0; while [ $rep -lt "$REPS" ]; do
		rep=$((rep + 1))
		lg=$(boot rw 2>&1 | sed -n 's/.*login ~\([0-9]*\)s.*/\1/p' | head -1)
		sv=$(measure_serve | sed -n 's/SERVE_S=//p' | head -1)
		echo "  $name rep$rep: serve=${sv}s login~=${lg}s"
		[ "$sv" -lt "$best" ] 2>/dev/null && best=$sv
	done
	echo "$name: best serve=${best}s"
	eval "${name}_SERVE=$best"
}

scrub_stage
stage_bundle System Test app.Test "" boottimeprobe boottimeprobe >/dev/null

echo "===== SERIAL (baseline: native launch AFTER /etc/rc) ====="
run_variant SERIAL "$SB_SERIAL"
echo "===== OVERLAP (native launch parallel with /etc/rc) ====="
run_variant OVERLAP "$SB_OVERLAP"

echo "===== RESULT: time until the capability plane serves storage ====="
echo "serial  native-after-rc : serve=${SERIAL_SERVE}s"
echo "overlap native-with-rc  : serve=${OVERLAP_SERVE}s"
echo DONE
