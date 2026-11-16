#!/bin/sh
# vm-provider.sh: the kernel tier is proved, on the host from the stage's
# binaries and in the guest from the booted file and the ledger's knobs.
# Runs the actual blocks of vm-provider.sh; no guest.  The guest commands
# (sysctl, sha256, ps, kenv) are shell functions here.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fail() { echo "FAIL: $*"; exit 1; }

sed -n '/^# --- kernel tier, host side/,/^# --- end of the kernel tier, host side$/p' \
    "$root/vm-provider.sh" > "$work/host.sh"
grep -q 'check-test-kernel.sh' "$work/host.sh" || fail 'no host block'
sed -n '/^# --- test-kernel proof/,/^# --- end of the test-kernel proof$/p' \
    "$root/vm-provider.sh" > "$work/guest.sh"
grep -q 'TEST_KERNEL_PROOF_PASS' "$work/guest.sh" || fail 'no guest block'

# A stage: plain, or carrying the first live row's marker.
marker=$(sh "$root/../../../release/scripts/check-test-kernel.sh" \
    -l "$root/../../../sys/conf/test-options" -L |
    awk -F '|' '$2 == "live" { print $5; exit }')
[ -n "$marker" ] || fail 'the ledger has no live row'
stage() {
	rm -rf "$work/stage"
	mkdir -p "$work/stage/boot/kernel"
	printf 'ELF\0%s\0' "$1" > "$work/stage/boot/kernel/kernel"
}
# host tier: runs the block as vm-provider.sh would; prints its variables.
host() {
	( cd "$work" && KERNEL_TIER=$1 sh -c '
	    die() { echo "vm-provider: $*" >&2; exit 2; }
	    stage=$1 work=$2
	    . "$3"
	    echo "host=$test_kernel_host option=$test_option sha=$kernel_sha256 knobs=$test_knobs"
	' "$root/vm-provider.sh" "$work/stage" "$work" "$work/host.sh" )
}

stage 'plain kernel'
out=$(host auto) || fail "host auto on a plain kernel: $out"
echo "$out" | grep -q '^host=no option=none ' || fail "plain kernel: $out"
sha=$(sha256 -q "$work/stage/boot/kernel/kernel")
echo "$out" | grep -q "sha=$sha " || fail "plain kernel hash: $out"
knobs=$(echo "$out" | sed -n 's/.* knobs=//p')
[ -n "$knobs" ] || fail 'no knobs listed for the live rows'
host main > /dev/null || fail 'main tier refused a plain kernel'
if host test > "$work/err" 2>&1; then fail 'test tier accepted a plain kernel'; fi
grep -q 'carries no test-kernel option' "$work/err" || fail "test tier: $(cat "$work/err")"

stage "$marker"
out=$(host auto) || fail "host auto on a test kernel: $out"
echo "$out" | grep -q '^host=yes option=[A-Z0-9_]* ' || fail "test kernel: $out"
host test > /dev/null || fail 'test tier refused a test kernel'
if host main > "$work/err" 2>&1; then fail 'main tier accepted a test kernel'; fi
grep -q 'was built with options' "$work/err" || fail "main tier: $(cat "$work/err")"

# A boot directory the check cannot read stops the run.
rm -rf "$work/stage/boot"
if host auto > "$work/err" 2>&1; then fail 'an unreadable stage passed'; fi

# guest tier host-flag booted-sha present-knobs: the guest block's verdict.
guest() {
	sh -c '
	    R=$1/results; mkdir -p "$R"
	    KERNEL_TIER=$2 TEST_KERNEL_HOST=$3 TEST_OPTION=X KERNEL_SHA256=good
	    TEST_KNOBS="debug.a.knob debug.b.knob" PLANE_OFF=0 booted=$4 stub_knobs=$5
	    sysctl() {
		case "$1 $2" in
		"-n kern.bootfile") echo /boot/kernel/kernel ;;
		"-N "*) case " $stub_knobs " in *" $2 "*) return 0 ;; esac; return 1 ;;
		"-n debug."*) case " $stub_knobs " in *" $2 "*) echo 1; return 0 ;; esac; return 1 ;;
		*) echo stub ;;
		esac
	    }
	    sha256() { echo "$booted"; }
	    ps() { echo init; }
	    kenv() { echo NO; }
	    kldstat() { printf "Id Refs\n 1 mac_test\n"; }
	    . "$6"
	' guest "$work" "$1" "$2" "$3" "$4" "$work/guest.sh"
}
both='debug.a.knob debug.b.knob'
guest test yes good "$both" | grep -qx TEST_KERNEL_PROOF_PASS || fail 'test kernel, all knobs'
guest test yes good "$both" | grep -qx 'TIER_INFO: TEST_KERNEL=yes' || fail 'test kernel label'
guest main no good '' | grep -qx TEST_KERNEL_PROOF_PASS || fail 'main kernel, no knobs'
guest main no good '' | grep -qx 'TIER_INFO: TEST_KERNEL=no' || fail 'main kernel label'
guest auto yes good "$both" | grep -qx TEST_KERNEL_PROOF_PASS || fail 'auto, test kernel'
# Another file booted, a knob missing on a test kernel, a knob on a main one.
guest test yes other "$both" | grep -q '^TEST_KERNEL_PROOF_FAIL' || fail 'other booted file'
guest auto no other '' | grep -qx 'TIER_INFO: TEST_KERNEL=inconsistent' || fail 'other file label'
guest test yes good 'debug.a.knob' | grep -q '^TEST_KERNEL_PROOF_FAIL' || fail 'missing knob'
guest main no good 'debug.b.knob' | grep -q '^TEST_KERNEL_PROOF_FAIL' || fail 'stray knob'
guest test no good '' | grep -q '^TEST_KERNEL_PROOF_FAIL' || fail 'tier test on a main kernel'
[ -s "$work/results/tier.txt" ] || fail 'no tier.txt written'
grep -q '^kernel-sha256 host=good booted=' "$work/results/tier.txt" || fail 'tier.txt content'
grep -qx 'mac-modules=mac_test ' "$work/results/tier.txt" || fail 'tier.txt MAC modules'

echo 'PASS the kernel tier is proved on the host and in the guest'
