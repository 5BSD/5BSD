#!/bin/sh
# vm-provider.sh: the kernel tier is proved, on the host from the stage's
# binaries and in the guest from the booted file, the kernel version and the
# ledger's knobs.  Runs the actual blocks of vm-provider.sh; no guest.  The
# guest commands (sysctl, sha256, ps, kenv, kldstat) are shell functions
# here.
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
# The two verdict conditions about the proof, as one test.
sed -n "/grep -acx 'TEST_KERNEL_PROOF_PASS'/,/TEST_KERNEL_PROOF_FAIL' &&/p" \
    "$root/vm-provider.sh" > "$work/verdict.sh"
[ "$(wc -l < "$work/verdict.sh")" -eq 2 ] || fail 'no verdict lines'
echo true >> "$work/verdict.sh"

# A stage: plain, or carrying the first live row's marker, with a version.
marker=$(sh "$root/../../../release/scripts/check-test-kernel.sh" \
    -l "$root/../../../sys/conf/test-options" -L |
    awk -F '|' '$2 == "live" { print $5; exit }')
[ -n "$marker" ] || fail 'the ledger has no live row'
version='5BSD 16.0-CURRENT #0 lg3-n1-0123456789ab: Mon Nov 16 00:00:00 UTC 2026'
stage() {
	rm -rf "$work/stage"
	mkdir -p "$work/stage/boot/kernel"
	# The marker first, as a real kernel has it: it too begins "@(#)5BSD ".
	printf 'ELF\0%s\0@(#)%s\0' "$1" "$version" > "$work/stage/boot/kernel/kernel"
}
# host [VAR=value...]: runs the block as vm-provider.sh would, with the
# given environment; prints its variables.
host() {
	( cd "$work" && env -u KERNEL_TIER -u PLANE_OFF "$@" sh -c '
	    die() { echo "vm-provider: $*" >&2; exit 2; }
	    stage=$1 work=$2
	    . "$3"
	    echo "host=$test_kernel_host option=$test_option sha=$kernel_sha256 knobs=$test_knobs"
	    echo "version=$kernel_version"
	' "$root/vm-provider.sh" "$work/stage" "$work" "$work/host.sh" )
}

stage "@(#)5BSD DQ_TEST_OPEN_NOT_A_ROW plain"
out=$(host) || fail "default tier on a plain kernel: $out"
echo "$out" | grep -q '^host=no option=none ' || fail "plain kernel: $out"
sha=$(sha256 -q "$work/stage/boot/kernel/kernel")
echo "$out" | grep -q "sha=$sha " || fail "plain kernel hash: $out"
echo "$out" | grep -qxF "version=$version" || fail "plain kernel version: $out"
knobs=$(echo "$out" | sed -n 's/.* knobs=//p')
[ -n "$knobs" ] || fail 'no knobs listed for the live rows'
host KERNEL_TIER=main > /dev/null || fail 'main tier refused a plain kernel'
if host KERNEL_TIER=test > "$work/err" 2>&1; then fail 'test tier accepted a plain kernel'; fi
grep -q 'carries no test-kernel option' "$work/err" || fail "test tier: $(cat "$work/err")"
for tier in auto Test; do
	if host KERNEL_TIER=$tier > "$work/err" 2>&1; then fail "KERNEL_TIER=$tier accepted"; fi
	grep -q 'KERNEL_TIER must be main or test' "$work/err" || fail "KERNEL_TIER=$tier: $(cat "$work/err")"
done
# A test-kernel marker outside boot/kernel: the two checks disagree.
mkdir -p "$work/stage/boot/kernel.old"
printf 'ELF\0%s\0' "$marker" > "$work/stage/boot/kernel.old/kernel"
if host > "$work/err" 2>&1; then fail 'a test kernel.old passed'; fi
grep -q 'boot directory .* disagrees with its boot/kernel' "$work/err" || fail "kernel.old: $(cat "$work/err")"

stage "$marker"
out=$(host KERNEL_TIER=test) || fail "test tier on a test kernel: $out"
echo "$out" | grep -q '^host=yes option=[A-Z0-9_]* ' || fail "test kernel: $out"
# A test kernel is refused unless the test tier is asked for: by default,
# in the enforced plane-off tier, and when main is named.
for env in '' PLANE_OFF=1 KERNEL_TIER=main 'PLANE_OFF=1 KERNEL_TIER=main'; do
	if host $env > "$work/err" 2>&1; then fail "a test kernel ran with [$env]"; fi
	grep -q 'a test kernel runs only with KERNEL_TIER=test' "$work/err" ||
	    fail "[$env]: $(cat "$work/err")"
done
# A kernel without a version string stops the run.
printf 'ELF\0no version\0' > "$work/stage/boot/kernel/kernel"
if host > "$work/err" 2>&1; then fail 'a kernel without a version passed'; fi
grep -q 'version string' "$work/err" || fail "no version: $(cat "$work/err")"
# A boot directory the check cannot read stops the run.
rm -rf "$work/stage/boot"
if host > "$work/err" 2>&1; then fail 'an unreadable stage passed'; fi

# guest tier host-flag booted-sha booted-version knobs: the guest block.
guest() {
	sh -c '
	    R=$1/results; mkdir -p "$R"; rm -f "$R/tier.txt"
	    KERNEL_TIER=$2 TEST_KERNEL_HOST=$3 TEST_OPTION=X KERNEL_SHA256=good
	    KERNEL_VERSION="5BSD good" TEST_KNOBS="debug.a.knob debug.b.knob"
	    PLANE_OFF=0 booted=$4 booted_v=$5 stub_knobs=$6
	    sysctl() {
		case "$1 $2" in
		"-n kern.bootfile") echo /boot/kernel/kernel ;;
		"-n kern.version") printf "%s\n    builder@host:/obj/GENERIC\n" "$booted_v" ;;
		"-N "*) case " $stub_knobs " in *" $2 "*) return 0 ;; esac; return 1 ;;
		"-n debug."*) case " $stub_knobs " in *" $2 "*) echo 1; return 0 ;; esac; return 1 ;;
		*) echo stub ;;
		esac
	    }
	    sha256() { echo "$booted"; }
	    ps() { echo init; }
	    kenv() { echo NO; }
	    kldstat() { printf "Id Refs\n 1 mac_test\n"; }
	    . "$7"
	' guest "$work" "$1" "$2" "$3" "$4" "$5" "$work/guest.sh"
}
both='debug.a.knob debug.b.knob'
v='5BSD good'
guest test yes good "$v" "$both" | grep -qx TEST_KERNEL_PROOF_PASS || fail 'test kernel, all knobs'
guest test yes good "$v" "$both" | grep -qx 'TIER_INFO: TEST_KERNEL=yes' || fail 'test kernel label'
guest main no good "$v" '' | grep -qx TEST_KERNEL_PROOF_PASS || fail 'main kernel, no knobs'
guest main no good "$v" '' | grep -qx 'TIER_INFO: TEST_KERNEL=no' || fail 'main kernel label'
# Another file booted, another kernel loaded, a knob missing on a test
# kernel, a knob on a main one, a tier the host did not find.
guest test yes other "$v" "$both" | grep -q '^TEST_KERNEL_PROOF_FAIL' || fail 'other booted file'
guest main no good '5BSD other' '' | grep -q '^TEST_KERNEL_PROOF_FAIL' || fail 'other kernel version'
guest main no good '5BSD other' '' | grep -qx 'TIER_INFO: TEST_KERNEL=inconsistent' || fail 'other version label'
guest test yes good "$v" 'debug.a.knob' | grep -q '^TEST_KERNEL_PROOF_FAIL' || fail 'missing knob'
guest main no good "$v" 'debug.b.knob' | grep -q '^TEST_KERNEL_PROOF_FAIL' || fail 'stray knob'
guest test no good "$v" '' | grep -q '^TEST_KERNEL_PROOF_FAIL' || fail 'tier test on a main kernel'
guest main yes good "$v" "$both" | grep -q '^TEST_KERNEL_PROOF_FAIL' || fail 'tier main on a test kernel'
guest main no good "$v" '' > /dev/null
t=$work/results/tier.txt
[ -s "$t" ] || fail 'no tier.txt written'
grep -q '^kernel-sha256 host=good booted=good ' "$t" || fail 'tier.txt hash'
grep -qx 'kernel-version booted=5BSD good' "$t" || fail 'tier.txt version'
grep -qx 'mac-modules=mac_test ' "$t" || fail 'tier.txt MAC modules'

# The stack tier: a test kernel, plane off, test issuers on, not anchored.
sed -n '/^# --- stack tier/,/^# --- end of the stack tier$/p' \
    "$root/vm-provider.sh" > "$work/stack.sh"
grep -q 'stack_tier=1' "$work/stack.sh" || fail 'no stack-tier block'
stack() {
	sh -c '
	    R=$1/results; mkdir -p "$R"; : > "$R/tier.txt"
	    test_kernel=$2 PLANE_OFF=$3 switch=$4 st=$5 KYUA_VARS=x
	    sysctl() {
		case "$2" in
		kern.mac_capability.test_issuer) [ -n "$switch" ] && echo "$switch" ;;
		kern.mac_capability.test_issuer_state) [ -n "$st" ] && echo "$st" ;;
		kern.mac_capability.test_issuers) echo 3 ;;
		esac
	    }
	    . "$6"
	    echo "vars=$KYUA_VARS"
	' stack "$work" "$@" "$work/stack.sh"
}
stack yes 1 1 none | grep -qx 'TIER_INFO: stack-tier=yes' || fail 'stack tier not recognised'
stack yes 1 1 test | grep -qx 'vars=x test_suites.FreeBSD.stack_tier=1' || fail 'stack_tier not passed'
stack yes 1 1 anchored | grep -qx 'TIER_INFO: stack-tier=no' || fail 'anchored boot labelled stack'
stack yes 0 1 none | grep -qx 'TIER_INFO: stack-tier=no' || fail 'plane-on labelled stack'
stack yes 1 0 none | grep -qx 'TIER_INFO: stack-tier=no' || fail 'switch off labelled stack'
stack no 1 '' '' | grep -qx 'vars=x' || fail 'main kernel labelled stack'

# The verdict: exactly one PASS line and no FAIL line.
verdict() { printf "$1" > "$work/log"; log=$work/log sh "$work/verdict.sh"; }
verdict 'x\nTEST_KERNEL_PROOF_PASS\ny\n' || fail 'verdict: one PASS'
if verdict 'TEST_KERNEL_PROOF_FAIL: tier main\nTEST_KERNEL_PROOF_PASS\n'; then fail 'verdict: FAIL then PASS'; fi
if verdict 'TEST_KERNEL_PROOF_PASS\nTEST_KERNEL_PROOF_PASS\n'; then fail 'verdict: two PASS'; fi
if verdict 'nothing\n'; then fail 'verdict: no PASS'; fi

echo 'PASS the kernel tier is proved on the host and in the guest'
