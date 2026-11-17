#!/bin/sh
# vm-provider.sh REROOT=1: the host refuses a reroot stage it cannot run; the
# guest reroots into Capsule only after the extra script passed on the
# plane-off boot, restores its results after the reroot, and the verdict
# needs the rerooted Capsule.  Runs the actual blocks of vm-provider.sh with
# kenv, reboot and sync as shell functions; no guest.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fail() { echo "FAIL: $*"; exit 1; }
block() {
	sed -n "$1" "$root/vm-provider.sh" | sed "s|/var/db/|$work/db/|g" > "$work/$2"
	[ -s "$work/$2" ] || fail "no $2 block"
}
block '/^# --- reroot request/,/^# --- end of the reroot request$/p' request.sh
block '/^# --- reroot, after/,/^if \[ "\$rerooted" = no \]; then$/p' after.sh
echo fi >> "$work/after.sh"
block '/^# --- reroot, before/,/^# --- end of the reroot$/p' before.sh
sed -i '' "s|-C /tmp|-C $work/tmp|" "$work/before.sh" "$work/after.sh"
sed -n '/{ \[ "\$reroot" = 0 \] ||/,+1p' "$root/vm-provider.sh" |
    sed 's/; }; } \&\&$/; }; }/' > "$work/verdict.sh"
[ "$(wc -l < "$work/verdict.sh")" -eq 2 ] || fail 'no verdict lines'

# The host side.
request() {
	env -u REROOT -u KERNEL_TIER -u STACK_TIER "$@" sh -c '
	    die() { echo "vm-provider: $*" >&2; exit 2; }
	    plane_off=${PO:-0} extra_script=${ES:-}
	    . "$1"; echo "reroot=$reroot"' request "$work/request.sh"
}
request | grep -qx 'reroot=0' || fail 'no request is not reroot=0'
request REROOT=1 PO=1 KERNEL_TIER=test ES=x | grep -qx 'reroot=1' ||
    fail 'a possible reroot refused'
for env in 'REROOT=1 KERNEL_TIER=test ES=x' 'REROOT=1 PO=1 ES=x' \
    'REROOT=1 PO=1 KERNEL_TIER=test' 'REROOT=1 PO=1 KERNEL_TIER=test ES=x STACK_TIER=1'; do
	if request $env > "$work/err" 2>&1; then fail "[$env] accepted"; fi
	grep -q 'REROOT=1 needs PLANE_OFF=1' "$work/err" || fail "[$env]: $(cat "$work/err")"
done
if request REROOT=yes > "$work/err" 2>&1; then fail 'REROOT=yes accepted'; fi

# The guest side.
guest() {
	sh -c '
	    R=$1/tmp/kyua-results REROOT=$2 rerooted=$3
	    kenv() { case $1 in -q) echo NO ;; *) echo "kenv $*" ;; esac; }
	    reboot() { echo "reboot $*"; }
	    sync() { :; }
	    sleep() { :; }
	    ps() { echo capsule; }
	    tar() { command tar "$@"; }
	    set -- "$4"
	    cd /
	    . "$1"
	    echo "rerooted=$rerooted VM_REROOT=$VM_REROOT"
	' guest "$work" "$@"
}
mkdir -p "$work/db" "$work/tmp/kyua-results"
R=$work/tmp/kyua-results
echo 7 > "$R/extra.exit"
guest 1 no "$work/before.sh" > "$work/out"
grep -q '^REROOT_FAIL: the extra script failed before the reroot' "$work/out" ||
    fail "failed extra script: $(cat "$work/out")"
grep -q '^reboot' "$work/out" && fail 'rerooted after a failed extra script'
echo 0 > "$R/extra.exit"; echo before-output > "$R/extra.out"
guest 0 no "$work/before.sh" > "$work/out"
grep -q "^REROOT\|^reboot\|^kenv" "$work/out" && fail "REROOT=0 did something: $(cat "$work/out")"
guest 1 no "$work/before.sh" > "$work/out"
for l in REROOT_BEGIN 'kenv -u capability_plane' 'kenv init_path=/sbin/capsule' \
    'reboot -r' 'REROOT_FAIL: reboot -r returned'; do
	grep -qx "$l" "$work/out" || fail "before: no [$l]: $(cat "$work/out")"
done
[ -f "$work/db/vm-provider-reroot.tar" ] || fail 'results not saved'
# After the reroot /tmp is empty again.
rm -rf "$work/tmp"; mkdir -p "$work/tmp"
guest 1 no "$work/after.sh" > "$work/out"
grep -qx 'REROOT_AFTER: pid1=capsule capability_plane=NO' "$work/out" ||
    fail "after: $(cat "$work/out")"
grep -qx 'rerooted=yes VM_REROOT=after' "$work/out" || fail "after: $(cat "$work/out")"
[ "$(cat "$work/tmp/kyua-results/extra.before.out")" = before-output ] ||
    fail 'results not restored'
[ -e "$work/db/vm-provider-reroot.tar" ] && fail 'saved results left behind'
guest 1 no "$work/after.sh" | grep -qx 'rerooted=no VM_REROOT=before' ||
    fail 'a second boot counted as rerooted'
guest 0 no "$work/after.sh" | grep -qx 'rerooted=no VM_REROOT=none' ||
    fail 'REROOT=0 not VM_REROOT=none'

# The verdict needs Capsule as PID 1 after the reroot and no REROOT_FAIL.
verdict() { log=$work/log reroot=$1 sh "$work/verdict.sh"; }
printf 'REROOT_AFTER: pid1=capsule capability_plane=unset\n' > "$work/log"
verdict 1 || fail 'a good reroot not clean'
printf 'REROOT_AFTER: pid1=init capability_plane=unset\n' > "$work/log"
verdict 1 && fail 'a reroot into init clean'
printf 'REROOT_AFTER: pid1=capsule capability_plane=unset\nREROOT_FAIL: x\n' > "$work/log"
verdict 1 && fail 'REROOT_FAIL clean'
: > "$work/log"
verdict 1 && fail 'a reroot that never happened clean'
verdict 0 || fail 'REROOT=0 needs a reroot'
echo 'PASS the reroot stage is refused unless possible, reroots only after a passing extra script, and needs Capsule after it'
