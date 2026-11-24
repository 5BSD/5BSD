#!/bin/sh
# vm-provider.sh preloads ufs and cryptodev from the stage when its kernel
# does not compile them in (MINIMAL), since the plane refuses a late
# kldload; a kernel that has them gets nothing, and a stage that has
# neither the module nor its .ko stops the run.  Runs the actual block of
# vm-provider.sh on stages whose kernels are objects naming the modules'
# metadata symbols; no guest.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fail() { echo "FAIL: $*"; exit 1; }

sed -n '/^# --- base modules, host side/,/^# --- end of the base modules, host side$/p' \
    "$root/vm-provider.sh" > "$work/block.sh"
grep -q '_mod_metadata_md_' "$work/block.sh" || fail 'no base-modules block'
# Written to the image's loader.conf with the other preloads.
grep -q '^\[ -z "\$base_loader" \] || printf .*"\$x/loader.conf"$' \
    "$root/vm-provider.sh" || fail 'base_loader is not written to loader.conf'

# stage module...: a stage whose kernel compiles in the modules named and
# whose boot/kernel holds every .ko named in $KOS.
stage() {
	rm -rf "$work/stage"
	mkdir -p "$work/stage/boot/kernel"
	echo 'int kernel_marker;' > "$work/kernel.c"
	for m in "$@"; do
		echo "int _mod_metadata_md_$m;" >> "$work/kernel.c"
	done
	cc -c -o "$work/stage/boot/kernel/kernel" "$work/kernel.c" ||
	    fail 'cannot compile the kernel'
	for ko in ${KOS:-}; do
		: > "$work/stage/boot/kernel/$ko.ko"
	done
}
# run: the block as vm-provider.sh runs it; prints its report and then the
# loader.conf lines it adds.
run() {
	sh -c '
	    die() { echo "vm-provider: $*" >&2; exit 2; }
	    stage=$1 work=$2
	    . "$3"
	    printf "%s" "$base_loader"
	' run "$work/stage" "$work" "$work/block.sh"
}

# GENERIC: both compiled in, nothing preloaded.
KOS='ufs cryptodev' stage ufs cryptodev ufshci
out=$(run) || fail "GENERIC: $out"
[ "$out" = 'BASE_MODULES_HOST: preloaded=none' ] || fail "GENERIC: $out"
[ ! -e "$work/kernel-symbols" ] || fail 'the symbol listing was left behind'

# MINIMAL: neither compiled in; both preloaded from the stage.  A module
# whose name only begins with one of them (ufshci) is not it.
KOS='ufs cryptodev' stage ufshci cryptodev_x
out=$(run) || fail "MINIMAL: $out"
printf 'BASE_MODULES_HOST: preloaded=ufs cryptodev\nufs_load="YES"\ncryptodev_load="YES"\n' \
    > "$work/expected"
printf '%s\n' "$out" | diff -u "$work/expected" - || fail 'MINIMAL preloads'

# One compiled in, the other preloaded.
KOS=cryptodev stage ufs
out=$(run) || fail "ufs only: $out"
printf 'BASE_MODULES_HOST: preloaded=cryptodev\ncryptodev_load="YES"\n' > "$work/expected"
printf '%s\n' "$out" | diff -u "$work/expected" - || fail 'ufs-only preloads'

# Neither compiled in nor in the stage: the run stops.
KOS=ufs stage
if run > "$work/out" 2> "$work/err"; then fail 'a stage without cryptodev passed'; fi
grep -q "has no cryptodev module compiled in, and the stage has no boot/kernel/cryptodev.ko" \
    "$work/err" || fail "no cryptodev: $(cat "$work/err")"

# A kernel without a symbol table stops the run.
KOS='ufs cryptodev' stage
printf 'not an ELF file\n' > "$work/stage/boot/kernel/kernel"
if run > "$work/out" 2> "$work/err"; then fail 'an unreadable kernel passed'; fi
grep -q "cannot read the symbol table of the stage's kernel" "$work/err" ||
    fail "unreadable kernel: $(cat "$work/err")"

echo 'PASS ufs and cryptodev are preloaded exactly when the kernel lacks them'
