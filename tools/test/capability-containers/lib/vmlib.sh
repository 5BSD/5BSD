# Shared helpers for the capability-container VM proofs.  Sourced by every
# script under ../scripts.  Requires the rig in ../rig (qemu boot, console
# command bridge, image builder) and a guest root staged by installworld.
#
#   VM     rig working dir with bsd-guest.img and guestroot   (default ~/vm)
#   WORK   where logs and image-build output go              (default $VM/work)
#   TOP    this harness (set by the caller from $0)
set -u
: "${VM:=$HOME/vm}"; : "${WORK:=$VM/work}"; mkdir -p "$WORK"
R=$VM/guestroot; CONS=$VM/console.log; CBUF=$VM/console.in.buf
RIG=$TOP/rig; PROBES=$TOP/probes/bin

# Run a command on the guest console, print its stdout.  V "cmd" [timeout_s]
V() { sh "$RIG/vcmd.sh" "$1" "${2:-25}"; }

# Build the image from the guest root (kills any running guest first).
build_image() {
	local tag=$1
	sh "$RIG/build-image-authority.sh" > "$WORK/$tag-img.log" 2>&1; tail -1 "$WORK/$tag-img.log"
	grep -q "^IMAGE_OK" "$WORK/$tag-img.log" || { echo "IMAGE BUILD FAILED -- aborting"; exit 2; }
}

# Boot the image (arg "rw" persists writes), attach the console bridge after
# the loader has autobooted, wait for a login prompt.  Detects the stage-1
# "boot:" prompt (an image the boot blocks cannot read) and a panic.
boot() {
	pkill -9 -f qemu-system-x86_64 2>/dev/null; pkill -f 'nc 127.0.0.1 4321' 2>/dev/null; pkill -f 'console.in.buf' 2>/dev/null
	sleep 3; rm -f "$CONS" "$CBUF"; : > "$CONS"; : > "$CBUF"
	PORT=4321 nohup sh "$RIG/boot-qemu.sh" "$VM/bsd-guest.img" ${1:-} >/dev/null 2>&1 &
	sleep 30
	nohup sh -c "tail -f -c +0 $CBUF | nc 127.0.0.1 4321 > $CONS 2>&1" >/dev/null 2>&1 &
	local i try
	for try in 1 2 3; do sleep 15
		if tr -d '\r' < "$CONS" 2>/dev/null | tail -6 | grep -qE "^boot: *$|^Default: "; then
			echo "  STAGE1_PROMPT (try $try): $(tr -d '\r' < "$CONS" | grep -v '^\s*$' | head -8 | tr '\n' '|' | cut -c1-300)"
			printf '\r' >> "$CBUF"
		else break; fi
	done
	i=0; while [ $i -lt 60 ]; do sleep 3
		tr -d '\r' < "$CONS" 2>/dev/null | tail -20 | grep -qE "root@|# $" && break
		tr -d '\r' < "$CONS" 2>/dev/null | tail -20 | grep -qE "^db> |panic:" && { echo "PANIC"; tr -d '\r' < "$CONS" | grep -A12 "panic:" | head -30; return 1; }
		i=$((i+1)); done
	echo "  login ~$((i*3+30))s"
	[ $i -ge 60 ] && { echo "  BOOT TIMEOUT"; tr -d '\r' < "$CONS" | tail -12 | cut -c1-140; return 1; }
	sleep 6; printf '\r' >> "$CBUF"; sleep 2
}

# --- staging into the guest root -------------------------------------------
# METALOG lines for a bundle at $base with the given unit names.
meta_bundle() {
	local base=$1; shift
	echo "$base type=dir uname=root gname=wheel mode=0755"
	echo "$base/Bundle.ucl type=file uname=root gname=wheel mode=0644"
	echo "$base/Units type=dir uname=root gname=wheel mode=0755"
	local u; for u in "$@"; do
		echo "$base/Units/$u.unit type=dir uname=root gname=wheel mode=0755"
		echo "$base/Units/$u.unit/Unit.ucl type=file uname=root gname=wheel mode=0644"
		echo "$base/Units/$u.unit/bin type=dir uname=root gname=wheel mode=0755"
		echo "$base/Units/$u.unit/bin/$u type=file uname=root gname=wheel mode=0555"
	done
}
# Drop every staged test bundle (Test A B C Env B01..) and its METALOG lines.
scrub_stage() {
	chmod u+w "$R/METALOG"
	grep -vE 'Capabilities/(System|Apps)/(Test|A|B|C|Env|Late|B[0-9][0-9])\.cap|^\./root/Test\.cap\.bak' "$R/METALOG" > "$R/METALOG.new" && mv "$R/METALOG.new" "$R/METALOG"
	local n; for n in Test A B C Env Late B01 B02 B03 B04 B05 B06 B07 B08 B09 B10 B11 B12; do
		chmod -R u+w "$R/Capabilities/System/$n.cap" "$R/Capabilities/Apps/$n.cap" 2>/dev/null; rm -rf "$R/Capabilities/System/$n.cap" "$R/Capabilities/Apps/$n.cap"; done
	rm -rf "$R/root/Test.cap.bak"
}
# stage_bundle <root:System|Apps> <Name> <bundle_id> <groups-line> <unit> <probe> [unit-ucl-extra] [args-line]
# One-unit bundle running $probe (from $PROBES) as unit $unit.  Returns the dir.
stage_bundle() {
	local root=$1 name=$2 bid=$3 groups=$4 unit=$5 probe=$6 extra=${7:-} args=${8:-}
	local d=$R/Capabilities/$root/$name.cap
	mkdir -p "$d/Units/$unit.unit/bin"
	cp "$PROBES/$probe" "$d/Units/$unit.unit/bin/$unit"; chmod 0555 "$d/Units/$unit.unit/bin/$unit"
	printf 'schema = "org.5bsd.capability-bundle";\nschema_version = 1;\nbundle_id = "%s";\nversion = "1.0.0";\nsequence = 1;\nauthor = "5BSD";\npublisher = "org.5bsd.base";\nunits = ["%s"];\n%s\n' "$bid" "$unit" "$groups" > "$d/Bundle.ucl"
	printf 'activation { boot = true; }\nprogram = "%s";\n%s\nrestart = "never";\nuser = "root";\n%s\n' "$unit" "$args" "$extra" > "$d/Units/$unit.unit/Unit.ucl"
	meta_bundle "./Capabilities/$root/$name.cap" "$unit" >> "$R/METALOG"
	echo "$d"
}
# Snapshot+clone an anon-mounted store to read its files from the shell:
#   obs <dataset>  -> files visible under /mnt/obs on the guest (drop_obs to clean)
OBS() { echo "zfs destroy -r zroot/obsclone 2>/dev/null; zfs destroy $1@obs 2>/dev/null; zfs snapshot $1@obs && zfs clone -o mountpoint=/mnt/obs $1@obs zroot/obsclone"; }
DROP_OBS() { echo "zfs destroy -r zroot/obsclone 2>/dev/null; zfs destroy $1@obs 2>/dev/null"; }
