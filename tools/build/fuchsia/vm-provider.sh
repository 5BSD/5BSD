#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# vm-provider.sh -- FIDL provider validation in a disposable plane-on guest.
# Derived from the plane-on Kyua runner described in
# docs/book/src/develop/testing.md ("VM, plane on").  Before Kyua it exercises
# BSDTime through the live broker: activation, reads, unauthorized writes,
# denied core restart and repeated sessions.  KYUA_VARS passes -v settings (for example
# test_suites.FreeBSD.vm_clock_test=true so gate_test runs real clock gates).
#
# Boot a NO_ROOT-staged world under QEMU (TCG, disk
# snapshot) with the capability plane ON (Capsule as PID 1, SwitchBoard
# running, all providers converged), run the selected Kyua suites unattended
# from the root serial-console login, collect the results over the serial
# console and on a raw results disk, and power off through Capsule.
#
# usage: vm-provider.sh STAGE_DIR WORK_DIR "suite1 suite2 ..." [TIMEOUT_S]
#
#   STAGE_DIR  NO_ROOT installworld+distribution+installkernel root (METALOG).
#              It is only READ: overlay files live in WORK_DIR and are fed to
#              makefs through mtree "contents=" (manifest mode).
#   WORK_DIR   new directory (must not exist); image, serial log, results.
#   suites     paths or program:case filters relative to /usr/tests, e.g. "usr.sbin/BSDTime
#              usr.sbin/switchboard".  Each must have a Kyuafile in the stage.
#   TIMEOUT_S  host-side deadline for the whole VM (default 10800).
#
# Environment: FATAL_LOR (yes; no logs a lock order reversal without
# stopping the run), CPUS (default 8), MEM_MB (8192; 12288 when the suites
#   include sys/posixshm: its largepage_* cases need a free aligned 1 GB
#   range, and an 8 GB guest has only four, which incidental cached pages
#   can occupy, so ENOMEM there is expected), PARALLELISM (kyua, default 1),
#   with sys/dq (or a program under it) in the suites, imgact_binmisc and
#   dtraceall are preloaded for them; with sys/mac_capability or its
#   issuer-decision probe programs, dtraceall; with usr.sbin/bsd-build,
#   zfs (an md-backed pool gives one case ACLs); with sys/kern or
#   sys/kern/ptrace_sleep_test, fusefs (its presleep cases serve one),
#   ROOT_FS (ufs, the default, or zfs: a ZFS root pool for the suites that
#   require one, such as the Linux ptrace ones),
#   GATE_TIMEOUT (guest seconds to wait for provider convergence, 600),
#   REQUIRE_UNITS (space-separated SwitchBoard labels that must be "running"
#   before tests start; default: the twelve core providers that
#   software-application-guest.sh requires), QEMU, QEMU_DATA,
#   DRYRUN=1 (build and check the image, do not boot), LOADER_EXTRA (extra
#   loader.conf lines), SRC_IMAGE and PORTS_IMAGE (UFS images mounted
#   read-only at /usr/src and /usr/obj/5BSD-ports).
#   ISOLATION_ENFORCE=1 retains production device isolation for deployment
#   checks; the default 0 permits raw-device provider test fixtures.
#   With PLANE_OFF=1 the default is 1 (the enforced tier, below), and the
#   guest gate checks the booted value either way.
#   SCRATCH_DISK (auto, 1 or 0; default auto): a blank 1 GB disk with the
#   serial kyua-scratch for storage_test:disk_import_and_binding, attached
#   when a suite is usr.sbin/capsule or narrower (see the block below).
#   SYSCTL_WRITE (space-separated sysctl names; default none): the image's
#   system.Sysctl policy lets every client write these names through the
#   provider (the policy matches prefixes: each name also covers the
#   subtree under it, so name leaves).  The plane reserves the provider's isolated names
#   (kern.maxfiles) for the provider, so a test that must change one asks
#   the provider; the shipped policy grants no client a write.  For
#   sys/kern/kern_descrip_test:kern_maxfiles__increase:
#   SYSCTL_WRITE=kern.maxfiles with
#   KYUA_VARS=test_suites.FreeBSD.allow_sysctl_side_effects=1.
#   STACK_TIER=1 requires the stack tier: KERNEL_TIER=test, PLANE_OFF=1, and in
#   the guest kern.mac_capability.test_issuer=1 with the boot not anchored.
#   A run that asks for it and does not get it fails (STACK_TIER_FAIL) rather
#   than counting every stack case as deferred.
#   TESTS_SRC_ROOTS (space-separated checkout paths; default none): every
#   ELF test program of the stage must come from one checkout; a deliberate
#   overlay lists every checkout its programs come from, the main one
#   included.  Otherwise the run stops with STALE_TESTS before the image is
#   built (check-stage-tests.py prints each TESTS_SRC_ROOT).  Scripts and
#   data under usr/tests (Kyuafiles, atf-sh programs, dq_suites.subr,
#   *.expected) record no source path and are not checked.
#   KERNEL_TIER (main or test; default main): the kernel tier of the run.
#   main is GENERIC, or any kernel without a test-kernel option; test is
#   GENERIC-TEST, and must be asked for: a stage whose kernel carries a
#   test-kernel option is refused unless KERNEL_TIER=test.
#
# Kernel tier.  The main tiers (plane on, PLANE_OFF=1, ISOLATION_ENFORCE=1)
# boot a kernel without any option of the test-kernel option ledger
# (sys/conf/test-options); the knob tier boots GENERIC-TEST.  Which one a
# run had is proved, not taken from a name.  On the host,
# release/scripts/check-test-kernel.sh reads the stage's boot/kernel (a
# refusal means a test kernel) and its whole boot directory (which must
# agree), and the kernel file's SHA-256 and version string are recorded.  In
# the guest, the booted kern.bootfile must have that hash, kern.version must
# be that version, and the ledger's knobs for live options must exist
# exactly on a test kernel.  TEST_KERNEL=yes|no is printed only when all
# agree, and the run is not clean otherwise.  The guest writes the proof,
# every knob's value, the plane state and the MAC policy modules kldstat
# lists to tier.txt in the results, and appends the knobs again after the
# suites.
#
# Two tiers run tests/sys/mac_capability (docs/book/src/develop/testing.md):
# the plane-on run, where its isolation denial cases skip because the policy
# only traces denials, and the enforced tier, PLANE_OFF=1 (enforce=1), which
# runs them.  The second is an addition to the plane-on run, not a substitute.
#
# Why not /etc/rc.local: under Capsule, SwitchBoard runs /etc/rc as a oneshot
# under a temporary boot grant and launches the native capability units only
# after rc exits (usr.sbin/switchboard/startup.c run_rc_bootstrap).  A test
# started from rc.local would run before the plane converges and with rc's
# grant.  The supported unattended hook -- used by the software-authority
# rig (prepare-root.py / stage-vm.py / run-vm.py) -- is an autologin getty on
# ttyu0 whose root .profile runs the script, ending in `capsulectl poweroff`.
#
# v2: Capsule claims /dev/mac_capability through mac_capability_isolation at
# plane start (usr.sbin/capsule/mac_capability_claims.c), and the claim denies
# open(2) and stat(2) to every other process, root included.  The provider
# tests open the device to build their own channel, so the image boots with
# kern.mac_capability_isolation.enforce=0 (boot-only test mode; ownership
# denials stay enforced -- docs/book/src/operations/boot-knobs.md).  The gate
# checks that the tunable took effect and that root can open the device.
# Suites that start a test-local Capsule (capd_start_stack/capd_launch_capsule)
# still skip here by design: they need a guest with no Capsule running.
set -eu

usage() { sed -n '7,/^set -eu/p' "$0" | sed -e '/^set -eu/d' -e 's/^# \{0,1\}//' >&2; exit 64; }
die() { echo "vm-provider: $*" >&2; exit 2; }
[ $# -ge 3 ] && [ $# -le 4 ] || usage
stage=$1 work=$2 suites=$3 timeout=${4:-10800}
# First runnable emulator: $QEMU, the local build carrying the X86Access
# page-straddle fix (emulators/qemu patch-target_i386_tcg_access.c; unpatched
# TCG QEMU 11.1.2 corrupts guest memory), then the installed port.
qemu=
for q in ${QEMU:-} /usr/obj/5bsd-qemu-fstt/qemu-system-x86_64-fstt-fixed \
    /usr/local/bin/qemu-system-x86_64; do
	if "$q" --version >/dev/null 2>&1; then qemu=$q; break; fi
done
qemu_data=${QEMU_DATA:-/usr/local/share/qemu}
kyua_vars=${KYUA_VARS:-}
# PLANE_OFF=1: boot with capability_plane="NO" (stock init; the "VM, plane off"
# tier) for raw kernel-service suites.  EXTRA_SCRIPT: a host shell script run
# as root in the guest before Kyua; its output is captured in the results.
# EXTRA_DIR: a host directory whose regular files are installed executable in
# the guest under /root/vm-extra.d (for example legacy latency benches).
# REROOT=1 (with PLANE_OFF=1, KERNEL_TIER=test and EXTRA_SCRIPT): the reroot
#   stage.  The extra script runs twice, with VM_REROOT=before on the plane-off
#   boot and, once it exits 0, the guest reroots into Capsule as PID 1 with
#   the plane on (kenv -u capability_plane; kenv init_path=/sbin/capsule;
#   reboot -r) and runs it again with VM_REROOT=after, then the suites.  Both
#   runs must exit 0.  Otherwise VM_REROOT=none.
# SINGLE_USER_SHELL (a guest path): the run expects PID 1 to enter single-user
#   once (for example the extra script refusing a restart).  The serial port
#   becomes a QEMU socket chardev that still logs to serial.log, "entering
#   recovery" and the single-user shell prompt are no longer fatal, and the
#   monitor answers that prompt once with this path (printable ASCII only),
#   typed one byte per echo, which runs as the
#   single-user shell; its exit returns the guest to multi-user.  A second
#   prompt stops the run.  The run is clean only if the prompt was answered
#   and that shell printed a line SINGLE_USER_SHELL_PASS (its own checks).
plane_off=${PLANE_OFF:-0}
case "$plane_off" in 0|1) ;; *) echo "PLANE_OFF must be 0 or 1" >&2; exit 64;; esac
# No Capsule claims the device with the plane off, so that tier enforces the
# isolation policy unless told otherwise: its isolation suites need it.
if [ "$plane_off" = 1 ]; then
	isolation=${ISOLATION_ENFORCE:-1}
else
	isolation=${ISOLATION_ENFORCE:-0}
fi
case "$isolation" in 0|1) ;; *) echo "ISOLATION_ENFORCE must be 0 or 1" >&2; exit 64;; esac
extra_script=${EXTRA_SCRIPT:-}
[ -z "$extra_script" ] || [ -f "$extra_script" ] || die "no such EXTRA_SCRIPT: $extra_script"
extra_dir=${EXTRA_DIR:-}
[ -z "$extra_dir" ] || [ -d "$extra_dir" ] || die "no such EXTRA_DIR: $extra_dir"
# --- reroot request (tests/vm-provider-reroot.sh runs this block)
reroot=${REROOT:-0}
case $reroot in 0|1) ;; *) die "REROOT must be 0 or 1";; esac
[ "$reroot" = 0 ] ||
    { [ "$plane_off" = 1 ] && [ "${KERNEL_TIER:-main}" = test ] &&
      [ -n "$extra_script" ] && [ "${STACK_TIER:-0}" = 0 ]; } ||
    die "REROOT=1 needs PLANE_OFF=1, KERNEL_TIER=test and EXTRA_SCRIPT, without STACK_TIER=1"
# --- end of the reroot request
# LINUX_COMPAT_DIR: a host directory holding compat/linux/... (test data, e.g.
# the overlay staged by stage-linux-compat.sh); its tree is installed under
# /compat/linux with its symlinks and modes, and linprocfs and linsysfs are
# mounted at /compat/linux/proc and /compat/linux/sys.  The plane refuses a
# late kldload, so pass linux64_load, linprocfs_load and linsysfs_load in
# LOADER_EXTRA as well.
# SRC_IMAGE: a host UFS image of a source tree (for example makefs of a git
# archive), attached read-only as a third disk and mounted read-only at
# /usr/src, for suites that read the tree (usr.sbin/bsd-build).  The image
# is test data and is never written; without it the guest has no source tree.
# With it the guest is a build host, so the image also gets the empty standard
# object root build-bsd(8) writes to, /usr/obj/usr/src and its repo
# directory (the bsd_build_test cases that run build-bsd there skip without
# them).
src_image=${SRC_IMAGE:-}
if [ -n "$src_image" ]; then
	# die is defined further down.
	case $src_image in
	/*,*|[!/]*) echo "SRC_IMAGE must be an absolute path without a comma" >&2; exit 64;;
	esac
	[ -f "$src_image" ] || { echo "no such SRC_IMAGE: $src_image" >&2; exit 64; }
fi
# PORTS_IMAGE: likewise a UFS image of a ports tree, mounted read-only at
# /usr/obj/5BSD-ports (build-bsd's default ports checkout).  It follows the source
# image in disk order, so it requires SRC_IMAGE.
ports_image=${PORTS_IMAGE:-}
if [ -n "$ports_image" ]; then
	[ -n "$src_image" ] || { echo "PORTS_IMAGE requires SRC_IMAGE" >&2; exit 64; }
	case $ports_image in
	/*,*|[!/]*) echo "PORTS_IMAGE must be an absolute path without a comma" >&2; exit 64;;
	esac
	[ -f "$ports_image" ] || { echo "no such PORTS_IMAGE: $ports_image" >&2; exit 64; }
fi
linux_compat_dir=${LINUX_COMPAT_DIR:-}
if [ -n "$linux_compat_dir" ]; then
	[ -d "$linux_compat_dir/compat/linux" ] ||
	    die "LINUX_COMPAT_DIR has no compat/linux: $linux_compat_dir"
	linux_compat_dir=$(cd "$linux_compat_dir" && pwd)
	# Checked here, not in the manifest pipeline, where die cannot stop us.
	bad=$(cd "$linux_compat_dir" && find compat/linux -print | grep -v '^[A-Za-z0-9_./+-]*$' || true)
	[ -z "$bad" ] || die "LINUX_COMPAT_DIR has unsupported path names: $bad"
fi
case " $suites " in
*" sys/posixshm"*) mem_default=12288 ;;
*) mem_default=8192 ;;
esac
# The modules the dq suites need that nothing else preloads: the plane
# refuses a late kldload, and those suites fail (never skip) without
# them.  imgact_binmisc for dq_resolve_test's binmisc row, dtraceall for
# dq_dtrace_test and dq_socket_test's probes, and for the issuer-decision
# probe in authority_issuer_probe_test and authority_test_issuer_anchor_test.
# LOADER_EXTRA still carries
# the Linux modules, mac_test_hooks and the rest of the recipe (DQ chapter
# of the book, section 17); a module named twice is loaded once.
dq_loader=
case " $suites " in
*" sys/dq "*|*" sys/dq/"*)
	dq_loader='imgact_binmisc_load="YES"
dtraceall_load="YES"' ;;
*" sys/mac_capability "*|*" sys/mac_capability/authority_issuer_probe_test"*|\
*" sys/mac_capability/authority_test_issuer_anchor_test"*)
	dq_loader='dtraceall_load="YES"' ;;
esac
# bsd_build_test:generation_reconciliation runs its ACL subtest on an
# md-backed ZFS pool (GENERIC has no UFS_ACL); the plane refuses a late
# kldload of zfs.
case " $suites " in
*" usr.sbin/bsd-build "*|*" usr.sbin/bsd-build/bsd_build_test"*)
	dq_loader="${dq_loader:+$dq_loader
}zfs_load=\"YES\"" ;;
esac
# ptrace_sleep_test's presleep cases hold a lookup in a fusefs file system
# they serve; the plane refuses a late kldload of fusefs.
case " $suites " in
*" sys/kern "*|*" sys/kern/ptrace_sleep_test"*)
	dq_loader="${dq_loader:+$dq_loader
}fusefs_load=\"YES\"" ;;
esac
# SCRATCH_DISK (auto, 1 or 0; default auto): a blank 1 GB disk attached last,
# with the serial kyua-scratch, for the one case that destroys a disk,
# usr.sbin/capsule/storage_test:disk_import_and_binding.  The guest writes its
# device name to that case's scratch-device input, and the case refuses a disk
# whose ident is not kyua-scratch.  auto attaches it when a suite is
# usr.sbin/capsule, the program or the case (a wider selection such as
# usr.sbin gets no disk and the case skips as DEFERRED_GUEST_SETUP unless
# SCRATCH_DISK=1); zfs is then preloaded too (the plane refuses a late
# kldload).
scratch_disk=${SCRATCH_DISK:-auto}
case "$scratch_disk" in
auto)
	scratch_disk=0
	for s in $suites; do
		case "usr.sbin/capsule/storage_test:disk_import_and_binding" in
		"${s%/}"|"${s%/}"/*|"${s%/}":*)
			case "${s%/}" in
			usr.sbin/capsule*) scratch_disk=1 ;;
			esac ;;
		esac
	done ;;
0|1) ;;
*) echo "SCRATCH_DISK must be auto, 0 or 1" >&2; exit 64;;
esac
if [ "$scratch_disk" = 1 ]; then
	case "$dq_loader" in
	*zfs_load*) ;;
	*) dq_loader="${dq_loader:+$dq_loader
}zfs_load=\"YES\"" ;;
	esac
fi
cpus=${CPUS:-4} mem=${MEM_MB:-$mem_default} par=${PARALLELISM:-1} gate=${GATE_TIMEOUT:-600}
root_fs=${ROOT_FS:-ufs}
# ROOT_SIZE: the guest root filesystem (makefs -s; default 8g).  Long
# bsd-build runs with python and the source and ports images fill 8g.  The
# guest reports ROOT_DF before and after the suites.
root_size=${ROOT_SIZE:-8g}
case $root_size in [1-9]g|[1-9][0-9]g) ;; *) echo "ROOT_SIZE must be 1g to 99g" >&2; exit 64;; esac
case "$root_fs" in ufs|zfs) ;; *) echo "ROOT_FS must be ufs or zfs" >&2; exit 64;; esac
units=${REQUIRE_UNITS:-system.Log/bsdlog system.Network/bsdnetwork system.Trace/bsdtrace system.Filesystem/bsdfilesystem system.Audit/bsdaudit system.Time/bsdtime system.SystemExtension/bsdextension system.Notify/bsdnotify system.Device/bsddevice system.Power/bsdpower system.Sysctl/bsdsysctl system.Crypto/bsdcrypto}

isnum() { case $1 in ''|*[!0-9]*) return 1;; esac; [ "$1" -gt 0 ]; }
for n in "$timeout" "$cpus" "$mem" "$par" "$gate"; do isnum "$n" || die "not a positive integer: $n"; done
case $suites in *[!A-Za-z0-9_./:\ -]*|'') die "suite list may only contain [A-Za-z0-9_./:-] and spaces";; esac
case $units in *[!A-Za-z0-9_./\ -]*) die "REQUIRE_UNITS has unexpected characters";; esac
case $kyua_vars in *[!A-Za-z0-9_.=\ -]*) die "KYUA_VARS has unexpected characters";; esac
sysctl_write=${SYSCTL_WRITE:-}
case $sysctl_write in *[!A-Za-z0-9_.\ ]*) die "SYSCTL_WRITE has unexpected characters";; esac
tests_src_roots=${TESTS_SRC_ROOTS:-}
case $tests_src_roots in *[!A-Za-z0-9_./+\ -]*) die "TESTS_SRC_ROOTS has unexpected characters";; esac
sysctl_conf=Capabilities/System/Sysctl.cap/Units/bsdsysctl.unit/Config/sysctl.conf

stage=$(cd "$stage" 2>/dev/null && pwd) || die "no stage dir"
[ -f "$stage/METALOG" ] || die "no METALOG in $stage (not a NO_ROOT stage)"
# makefs does not infer root permissions from the staging directory. Losing
# the "." record produces a root that unprivileged services cannot traverse;
# fexecve then fails loading the interpreter after replacing the old vmspace.
awk '
    ($1 == "." || $1 == "./") && !seen++ {
        for (i = 2; i <= NF; i++) {
            if ($i == "type=dir") directory = 1;
            if ($i ~ /^mode=0*[0-7]+$/ && $i ~ /[1357]$/) searchable = 1;
        }
    }
    END { exit !(seen && directory && searchable) }
' "$stage/METALOG" || die "METALOG must explicitly describe a searchable root directory (mode=0755)"
for f in sbin/capsule boot/kernel/kernel boot/pmbr boot/gptboot usr/bin/kyua usr/tests/Kyuafile; do
	[ -e "$stage/$f" ] || die "stage lacks /$f"
done
[ -L "$stage/usr/sbin/capsulectl" ] || [ -x "$stage/usr/sbin/capsulectl" ] || die "stage lacks /usr/sbin/capsulectl"
grep -q '^\./Capabilities/Run ' "$stage/METALOG" || die "METALOG has no ./Capabilities/Run"
grep -qE '^\./etc/rc( |$)' "$stage/METALOG" || die "/etc/rc not in METALOG: stage skipped 'make distribution'"
for s in $suites; do
	case $s in -*|/*|*..*) die "suite must be relative to /usr/tests without '..' or a leading '-': $s";; esac
	program=${s%%:*}
	case $s in
	*:*)
		case_name=${s#*:}
		case $case_name in ''|*[!A-Za-z0-9_]*) die "invalid test case name: $s";; esac
		[ -n "$program" ] && [ -f "$stage/usr/tests/$program" ] &&
		    [ -x "$stage/usr/tests/$program" ] || die "no such test program in stage: $s"
		;;
	*)
		[ -f "$stage/usr/tests/$program/Kyuafile" ] ||
		    { [ -f "$stage/usr/tests/$program" ] && [ -x "$stage/usr/tests/$program" ]; } ||
		    die "no such suite in stage: $s"
		;;
	esac
done
# Every ELF test program of the stage must come from one checkout (or from
# the checkouts TESTS_SRC_ROOTS names): a stage copied forward with only
# some test directories reinstalled runs another branch's tests under the
# oracles (check-stage-tests.py; 5bsd-issues
# 2026-11-18-guest-stage-stale-tests-sys-file-binaries.md).  Scripts and
# data files are not checked.
set --
for r in $tests_src_roots; do set -- "$@" --allow "$r"; done
st=0; python3.12 -I "$(dirname "$0")/check-stage-tests.py" "$stage" "$@" || st=$?
case $st in
0)	;;
3)	die "STALE_TESTS: the stage's ELF test programs are not from one checkout (see above)" ;;
*)	die "check-stage-tests.py could not check the stage (exit $st)" ;;
esac
[ -n "$qemu" ] || die "no runnable QEMU (set QEMU=)"
echo "qemu: $qemu ($("$qemu" --version | head -n 1))"
[ -d "$qemu_data" ] || die "no QEMU firmware dir $qemu_data"
[ ! -e "$work" ] || die "work dir exists: $work"
mkdir -p "$work"
work=$(cd "$work" && pwd)
[ ${#work} -le 80 ] || die "work path too long for the QMP UNIX socket: $work"

# ------------------------------------------------------------ kernel tier ---
# The binary check of the source tree this runner belongs to, run twice: on
# the stage's boot/kernel (the kernel and its modules, which decide the
# tier) and on the whole boot directory (which must agree).  Exit 0, no
# test-kernel option; 1 with "was built with options X", a test kernel;
# anything else is a check that read nothing, and the run stops.
# --- kernel tier, host side (tests/vm-provider-test-kernel-proof.sh runs this block)
kernel_tier=${KERNEL_TIER:-main}
stack_tier_request=${STACK_TIER:-0}
case $stack_tier_request in 0|1) ;; *) die "STACK_TIER must be 0 or 1";; esac
[ "$stack_tier_request" = 0 ] ||
    { [ "$kernel_tier" = test ] && [ "${PLANE_OFF:-0}" = 1 ]; } ||
    die "STACK_TIER=1 needs KERNEL_TIER=test and PLANE_OFF=1"
case $kernel_tier in main|test) ;; *) die "KERNEL_TIER must be main or test";; esac
src_root=$(cd "$(dirname "$0")/../../.." && pwd)
tk_check=$src_root/release/scripts/check-test-kernel.sh
tk_ledger=$src_root/sys/conf/test-options
[ -f "$tk_check" ] && [ -f "$tk_ledger" ] ||
    die "no release/scripts/check-test-kernel.sh or sys/conf/test-options in $src_root"
# tk_run mode path name: sets tk_found (yes or no) and tk_option.
tk_run() {
	tk_status=0
	sh "$tk_check" -l "$tk_ledger" "$1" "$2" > "$work/test-kernel-check-$3.out" \
	    2> "$work/test-kernel-check-$3.err" || tk_status=$?
	case $tk_status in
	0)	tk_found=no tk_option=none ;;
	1)	tk_option=$(sed -n 's/.* was built with options \([A-Z0-9_]*\), a test-kernel option$/\1/p' \
		    "$work/test-kernel-check-$3.err" | head -n 1)
		[ -n "$tk_option" ] || { cat "$work/test-kernel-check-$3.err" >&2
		    die "the test-kernel check could not read the stage's $3"; }
		tk_found=yes ;;
	*)	cat "$work/test-kernel-check-$3.err" >&2
		die "the test-kernel check of the stage's $3 failed (exit $tk_status)" ;;
	esac
}
tk_run -o "$stage/boot/kernel" kernel
test_kernel_host=$tk_found test_option=$tk_option
tk_run -d "$stage" boot
[ "$tk_found" = "$test_kernel_host" ] ||
    die "the stage's boot directory (test option: $tk_option) disagrees with its boot/kernel (test option: $test_option)"
kernel_sha256=$(sha256 -q "$stage/boot/kernel/kernel") || die "cannot hash the stage's kernel"
kernel_version=$(strings -a "$stage/boot/kernel/kernel" |
    sed -n 's/^@(#)\(5BSD [0-9][^ ]* #[0-9][0-9]* .*\)$/\1/p' | head -n 1)
case $kernel_version in
''|*[!A-Za-z0-9\ .:#_/+-]*) die "cannot read the version string of the stage's kernel";;
esac
test_knobs=$(sh "$tk_check" -l "$tk_ledger" -L |
    awk -F '|' '$2 == "live" && $6 != "-" { gsub(",", " ", $6); printf "%s ", $6 }')
case $test_knobs in *[!a-z0-9_.\ ]*) die "unexpected knob names in the ledger";; esac
echo "TEST_KERNEL_HOST: binary-check=$test_kernel_host option=$test_option kernel-sha256=$kernel_sha256"
echo "TEST_KERNEL_HOST: version=$kernel_version"
case $kernel_tier:$test_kernel_host in
main:yes) die "the stage's kernel was built with options $test_option: a test kernel runs only with KERNEL_TIER=test";;
test:no) die "KERNEL_TIER=test, but the stage's kernel carries no test-kernel option";;
esac
# --- end of the kernel tier, host side

# ---------------------------------------------------------------- overlay ---
x=$work/extra
mkdir -p "$x"
cat > "$x/loader.conf" <<EOF
console="comconsole"
autoboot_delay="1"
# Plane ON: no capability_plane="NO" here (docs/book/src/develop/testing.md,
# "VM, plane on").
# Test mode: Capsule's claim on /dev/mac_capability would otherwise refuse the
# provider tests' open(2) with EACCES.  Ownership checks stay enforced.
kern.mac_capability_isolation.enforce="$isolation"
EOF
# loader.conf.local is read after loader.conf.d/capsule.conf: no init
# fallback, so a Capsule that cannot start fails the run instead of silently
# booting stock init (plane off) and turning every provider test into a skip.
printf 'init_path="/sbin/capsule"\n' > "$x/loader.conf.local"
if [ "$plane_off" = 1 ]; then
	# No Capsule claims the device with the plane off; the isolation
	# setting chosen above (enforcing by default) is written as is.
	sed -i '' '/^# Test mode:/,/^kern.mac_capability_isolation.enforce=/d' \
	    "$x/loader.conf"
	printf 'kern.mac_capability_isolation.enforce="%s"\n' "$isolation" \
	    >> "$x/loader.conf"
	printf 'capability_plane="NO"\n' >> "$x/loader.conf"
	: > "$x/loader.conf.local"
fi
# LOADER_EXTRA: more loader.conf lines, e.g. if_vxlan_load="YES".
if [ "$root_fs" = zfs ]; then
	printf 'zfs_load="YES"\nvfs.root.mountfrom="zfs:kyuaroot"\n' >> "$x/loader.conf"
fi
[ -z "$dq_loader" ] || printf '%s\n' "$dq_loader" >> "$x/loader.conf"
[ -z "${LOADER_EXTRA:-}" ] || printf '%s\n' "$LOADER_EXTRA" >> "$x/loader.conf"
if [ -n "$extra_script" ]; then cp "$extra_script" "$x/extra.sh"; else : > "$x/extra.sh"; fi
cat > "$x/fstab" <<'EOF'
/dev/vtbd0p2	/	ufs	rw	1	1
tmpfs		/tmp	tmpfs	rw,mode=1777	0	0
tmpfs		/Capabilities/Run	tmpfs	rw,mode=0700	0	0
EOF
[ "$root_fs" = ufs ] || sed -i '' '/^\/dev\/vtbd0p2	\/	ufs/d' "$x/fstab"
# The third and fourth disks (after root and results); a failed mount stops rc.
[ -z "$src_image" ] || printf '/dev/vtbd2\t/usr/src\tufs\tro\t0\t0\n' >> "$x/fstab"
[ -z "$ports_image" ] || printf '/dev/vtbd3\t/usr/obj/5BSD-ports\tufs\tro\t0\t0\n' >> "$x/fstab"
if [ -n "$linux_compat_dir" ]; then
	cat >> "$x/fstab" <<'EOF'
linprocfs	/compat/linux/proc	linprocfs	rw	0	0
linsysfs	/compat/linux/sys	linsysfs	rw	0	0
EOF
fi
cat > "$x/rc.conf" <<'EOF'
hostname="kyua-planeon"
sendmail_enable="NONE"
sshd_enable="NO"
dumpdev="NO"
devmatch_enable="NO"
# Routed but unconnected NIC (hubport, no user netdev).
ifconfig_vtnet0="inet 10.0.2.15/24"
defaultrouter="10.0.2.2"
EOF
: > "$x/rc.local"		# rc.local must not run anything (see header)
printf 'ttyu0\t"/usr/libexec/getty kyuaplane"\tvt100\ton\tsecure\n' > "$x/ttys"
{ cat "$stage/etc/gettytab"; printf '\nkyuaplane|Kyua plane-on VM console:\\\n\t:al=root:tc=3wire:\n'; } > "$x/gettytab"
{ cat "$stage/root/.profile"; cat <<'EOF'

# vm-provider: one-shot serial-login action (interactive ttyu0 login only).
# A reroot (REROOT=1) need not clear /tmp: the results it saved under /var/db
# start the script again.
case "$-" in *i*) ;; *) return ;; esac
if [ "$(tty)" = /dev/ttyu0 ] && { [ ! -e /tmp/.kyua-planeon-started ] || [ -e /var/db/vm-provider-reroot.tar ]; }; then
	: > /tmp/.kyua-planeon-started
	sh /root/kyua-planeon.sh
	# 99: log out once so capsule respawns getty with the ambient channel.
	[ $? = 99 ] && exit
fi
EOF
} > "$x/profile"
# root's login shell may be zsh, which reads .zprofile rather than .profile.
{ cat "$stage/root/.zprofile"; cat <<'EOF'

# vm-provider: one-shot serial-login action (zsh login shells).
if [[ -o interactive ]] && [ "$(tty)" = /dev/ttyu0 ] && { [ ! -e /tmp/.kyua-planeon-started ] || [ -e /var/db/vm-provider-reroot.tar ]; }; then
	: > /tmp/.kyua-planeon-started
	sh /root/kyua-planeon.sh
	[ $? = 99 ] && exit
fi
EOF
} > "$x/zprofile"
printf '%s\n' "$suites" > "$x/suites"
if [ -n "$sysctl_write" ]; then
	# The default policy's empty write list becomes the given names.
	[ -f "$stage/$sysctl_conf" ] || die "SYSCTL_WRITE: stage lacks /$sysctl_conf"
	list=$(for n in $sysctl_write; do printf '"%s", ' "$n"; done | sed -e 's/, $//')
	awk -v list="$list" '
	    /^default[[:space:]]*\{/ { indef = 1 }
	    indef && !done && /^[[:space:]]*write[[:space:]]*=[[:space:]]*\[\];/ {
		sub(/\[\]/, "[" list "]"); done = 1
	    }
	    indef && /^\}/ { indef = 0 }
	    { print }
	    END { exit !done }
	' "$stage/$sysctl_conf" > "$x/sysctl.conf" ||
	    die "SYSCTL_WRITE: no empty default write list in /$sysctl_conf"
fi
cat > "$x/kyua-planeon.sh" <<EOF
#!/bin/sh
# Generated by vm-provider.sh; runs from the root autologin on ttyu0.
PATH=/sbin:/bin:/usr/sbin:/usr/bin; export PATH
GATE_TIMEOUT=$gate
PARALLELISM=$par
REQUIRE_UNITS="$units"
KYUA_VARS="$kyua_vars"
PLANE_OFF=$plane_off
ISOLATION_ENFORCE=$isolation
KERNEL_TIER=$kernel_tier
STACK_TIER_REQUEST=$stack_tier_request
TEST_KERNEL_HOST=$test_kernel_host
TEST_OPTION=$test_option
KERNEL_SHA256=$kernel_sha256
KERNEL_VERSION="$kernel_version"
TEST_KNOBS="$test_knobs"
REROOT=$reroot
SCRATCH_DISK=$scratch_disk
EOF
cat >> "$x/kyua-planeon.sh" <<'EOF'
R=/tmp/kyua-results
mkdir -p "$R"
echo KYUA_PLANEON_START
# --- reroot, after (REROOT=1): the reroot cleared /tmp; restore the results
# and skip what the plane-off boot already proved.
rerooted=no stack_tier=no
VM_REROOT=none
if [ "$REROOT" = 1 ]; then
	VM_REROOT=before
	if [ -e /var/db/vm-provider-reroot.tar ]; then
		rerooted=yes VM_REROOT=after
		tar -xf /var/db/vm-provider-reroot.tar -C /tmp
		rm -f /var/db/vm-provider-reroot.tar
		echo "REROOT_AFTER: pid1=$(ps -o comm= -p 1 | tr -d ' ') capability_plane=$(kenv -q capability_plane || echo unset)"
	fi
fi
export VM_REROOT
if [ "$rerooted" = no ]; then
# --- test-kernel proof (tests/vm-provider-test-kernel-proof.sh runs this block)
# The booted kernel must be the file the host checked, and the ledger's knobs
# must exist exactly when the host found a test-kernel option.
bootfile=$(sysctl -n kern.bootfile 2>/dev/null || echo unknown)
booted_sha256=$(sha256 -q "$bootfile" 2>/dev/null || echo unreadable)
booted_version=$(sysctl -n kern.version 2>/dev/null | head -n 1)
present= absent=
for k in $TEST_KNOBS; do
	if sysctl -N "$k" > /dev/null 2>&1; then present="$present $k"; else absent="$absent $k"; fi
done
test_kernel=inconsistent
if [ "$booted_sha256" = "$KERNEL_SHA256" ] && [ "$booted_version" = "$KERNEL_VERSION" ]; then
	if [ "$TEST_KERNEL_HOST" = yes ] && [ -z "$absent" ]; then
		test_kernel=yes
	elif [ "$TEST_KERNEL_HOST" = no ] && [ -z "$present" ]; then
		test_kernel=no
	fi
fi
{
	echo "KERNEL_TIER=$KERNEL_TIER"
	echo "TEST_KERNEL=$test_kernel"
	echo "test-kernel-binary-check host=$TEST_KERNEL_HOST option=$TEST_OPTION"
	echo "kernel-sha256 host=$KERNEL_SHA256 booted=$booted_sha256 bootfile=$bootfile"
	echo "kernel-version host=$KERNEL_VERSION"
	echo "kernel-version booted=$booted_version"
	echo "kern.ident=$(sysctl -n kern.ident 2>/dev/null || echo unknown)"
	for k in $TEST_KNOBS; do echo "knob $k=$(sysctl -n "$k" 2>/dev/null || echo absent)"; done
	echo "plane-off=$PLANE_OFF pid1=$(ps -o comm= -p 1 | tr -d ' ') capability_plane=$(kenv -q capability_plane || echo unset)"
	echo "kern.mac_capability_isolation.enforce=$(sysctl -n kern.mac_capability_isolation.enforce 2>/dev/null || echo unset)"
	echo "mac-modules=$(kldstat -v 2>/dev/null | awk '$2 ~ /^mac_/ { print $2 }' | sort -u | tr '\n' ' ')"
} > "$R/tier.txt"
sed 's/^/TIER_INFO: /' "$R/tier.txt"
case $KERNEL_TIER:$test_kernel in
main:no|test:yes) echo TEST_KERNEL_PROOF_PASS ;;
*) echo "TEST_KERNEL_PROOF_FAIL: tier $KERNEL_TIER, booted kernel $test_kernel" ;;
esac
# --- end of the test-kernel proof
# --- stack tier (tests/vm-provider-test-kernel-proof.sh runs this block)
# A test kernel, plane off, with test issuers on and the boot not anchored:
# test-local Capsule stacks get a unit issuer.  The cases that need one fail
# here, rather than skip, when it is missing (atf config stack_tier=1).
stack_tier=no
if [ "$test_kernel" = yes ] && [ "$PLANE_OFF" = 1 ] &&
    [ "$(sysctl -n kern.mac_capability.test_issuer 2>/dev/null)" = 1 ] &&
    [ "$(sysctl -n kern.mac_capability.test_issuer_state 2>/dev/null)" != anchored ]; then
	stack_tier=yes
	KYUA_VARS="$KYUA_VARS test_suites.FreeBSD.stack_tier=1"
fi
stack_issuers_before=$(sysctl -n kern.mac_capability.test_issuers 2>/dev/null || echo 0)
echo "stack-tier=$stack_tier" >> "$R/tier.txt"
echo "TIER_INFO: stack-tier=$stack_tier"
if [ "${STACK_TIER_REQUEST:-0}" = 1 ] && [ "$stack_tier" != yes ]; then
	echo "STACK_TIER_FAIL: the stack tier was requested and is not met:" \
	    "test kernel=$test_kernel plane-off=$PLANE_OFF" \
	    "test_issuer=$(sysctl -n kern.mac_capability.test_issuer 2>/dev/null || echo absent)" \
	    "state=$(sysctl -n kern.mac_capability.test_issuer_state 2>/dev/null || echo absent)"
fi
# --- end of the stack tier
if [ "$PLANE_OFF" = 1 ]; then
echo "PLANEOFF_PID1=$(ps -o comm= -p 1 | tr -d ' ')"
enf=$(sysctl -n kern.mac_capability_isolation.enforce 2>/dev/null || echo unset)
echo "PLANEOFF_ISOLATION_ENFORCE=$enf"
if [ "$enf" = "$ISOLATION_ENFORCE" ]; then echo PLANEOFF_READY; else
	echo "PLANEOFF_GATE: kern.mac_capability_isolation.enforce=$enf (want $ISOLATION_ENFORCE)"; fi
else
gate=PASS
pid1=$(ps -o comm= -p 1 | tr -d ' ')
echo "PLANEON_PID1=$pid1"
[ "$pid1" = capsule ] || { echo "PLANEON_GATE: PID 1 is not capsule"; gate=FAIL; }
cp=$(kenv -q capability_plane || true)
[ -z "$cp" ] || { echo "PLANEON_GATE: capability_plane=$cp"; gate=FAIL; }
pgrep -x switchboard >/dev/null || { echo "PLANEON_GATE: no switchboard process"; gate=FAIL; }
enf=$(sysctl -n kern.mac_capability_isolation.enforce 2>/dev/null || echo unset)
echo "PLANEON_ISOLATION_ENFORCE=$enf"
[ "$enf" = "$ISOLATION_ENFORCE" ] || { echo "PLANEON_GATE: kern.mac_capability_isolation.enforce=$enf (want $ISOLATION_ENFORCE)"; gate=FAIL; }
if [ "$ISOLATION_ENFORCE" = 1 ]; then
	if LC_ALL=C sh -c ': 3<>/dev/mac_capability' > "$R/device-open.txt" 2>&1; then
		echo 'PLANEON_GATE: root unexpectedly opened the claimed capability device'; gate=FAIL
	elif grep -Eq 'Permission denied|Operation not permitted' "$R/device-open.txt"; then
		echo PLANEON_DEVICE_ISOLATION_DENIED
	else
		echo 'PLANEON_GATE: device open failed for an unexpected reason'; cat "$R/device-open.txt"; gate=FAIL
	fi
else
	[ -c /dev/mac_capability ] || { echo "PLANEON_GATE: no /dev/mac_capability"; gate=FAIL; }
	sh -c ': 3<>/dev/mac_capability' 2>/dev/null ||
	    { echo "PLANEON_GATE: root cannot open /dev/mac_capability"; gate=FAIL; }
fi
# Bounded wait for provider convergence.
start=$(date +%s)
while :; do
	if switchboardctl status > "$R/switchboard-status.txt" 2>&1; then
		missing=
		for u in $REQUIRE_UNITS; do
			awk -v u="$u" '$1 == u && $2 == "running" { f=1 } END { exit !f }' \
			    "$R/switchboard-status.txt" || missing="$missing $u"
		done
		[ -z "$missing" ] && break
	else
		missing=" (switchboardctl status failed)"
	fi
	[ $(( $(date +%s) - start )) -ge "$GATE_TIMEOUT" ] && break
	sleep 5
done
cat "$R/switchboard-status.txt"
if [ -n "$missing" ]; then echo "PLANEON_GATE: not running:$missing"; gate=FAIL; fi
# Capsule hands the ambient lookup channel only to gettys forked after
# switchboard provides it.  If the console cannot reach even the user-visible
# system.Log, log out once so the respawned getty's login gets the channel.
# (Login sessions use a USER-domain channel: providers without
# visible = ["user"] are ENOENT there by design.)
if [ "$gate" = PASS ] && ! logger -t vm-provider lookup-probe > /dev/null 2>&1 && [ ! -e /tmp/.kyua-relogin ]; then
	: > /tmp/.kyua-relogin
	rm -f /tmp/.kyua-planeon-started
	echo PLANEON_RELOGIN_FOR_AMBIENT_LOOKUP
	exit 99
fi
echo "PLANEON_GATE_$gate"
# ------------------------------------------------ BSDTime through the broker
lc=PASS
# Controls: other providers reached through the same ambient lookup path.
for c in "logger -t vm-provider lookup-control" "BSDPowerctl states" "sysctlcmpctl get kern.ostype"; do
	if $c > "$R/control.out" 2>&1; then r=ok; else r="fail: $(head -n 1 "$R/control.out")"; fi
	echo "BSDTIME_CONTROL [$c]: $r"
done
t1=$(BSDTimectl get 2>"$R/get1.err") || { echo "BSDTIME: get failed: $(cat "$R/get1.err")"; lc=FAIL; }
echo "BSDTIME_GET1=$t1"
# The root console label is not granted set authority by the shipped policy;
# the provider itself must refuse (EPERM), not the lookup.
for c in "adjust 0.000001" "set 1"; do
	if BSDTimectl $c > "$R/write.out" 2>&1; then
		echo "BSDTIME: unauthorized $c succeeded"; lc=FAIL
	elif grep -q 'not permitted' "$R/write.out"; then
		echo "BSDTIME_UNAUTHORIZED_REFUSED [$c]: $(cat "$R/write.out")"
	else
		echo "BSDTIME: unauthorized $c failed for another reason: $(cat "$R/write.out")"; lc=FAIL
	fi
done
pid1=$(pgrep -x BSDTime | head -n 1)
echo "BSDTIME_PROVIDER_PID=$pid1"
# A core provider cannot be stopped at runtime (software-regressions-guest.sh);
# provider replacement happens through a release transaction and reboot.
if switchboardctl restart system.Time/bsdtime > "$R/restart.out" 2>&1; then
	echo "BSDTIME: core provider restart was permitted"; lc=FAIL
elif grep -q 'management class core' "$R/restart.out"; then
	echo "BSDTIME_CORE_RESTART_DENIED"
else
	echo "BSDTIME: restart failed unexpectedly: $(cat "$R/restart.out")"; lc=FAIL
fi
switchboardctl status 2>/dev/null |
    awk '$1 == "system.Time/bsdtime" && $2 == "running" { f=1 } END { exit !f }' ||
    { echo "BSDTIME: provider not running after denied restart"; lc=FAIL; }
[ "$(pgrep -x BSDTime | head -n 1)" = "$pid1" ] ||
    { echo "BSDTIME: provider process changed"; lc=FAIL; }
# Many short sessions against the live provider.
i=0
while [ $i -lt 200 ]; do
	if ! BSDTimectl get > "$R/session.out" 2> "$R/session.err"; then
		echo "BSDTIME_SESSION_FAILED index=$i: $(cat "$R/session.err")"
		break
	fi
	i=$((i + 1))
done
echo "BSDTIME_SESSIONS=$i"
[ "$i" = 200 ] || lc=FAIL
if t2=$(BSDTimectl get 2> "$R/get2.err"); then
	awk -v a="${t1%%.*}" -v b="${t2%%.*}" 'BEGIN { exit !(b >= a && a > 0) }' ||
	    { echo "BSDTIME: clock reads not monotonic"; lc=FAIL; }
else
	echo "BSDTIME: second get failed: $(cat "$R/get2.err")"; lc=FAIL
fi
echo "BSDTIME_LIFECYCLE_$lc"
fi
fi # rerooted = no
if [ -s /root/vm-extra.sh ]; then
	echo EXTRA_SCRIPT_BEGIN
	( set +e; sh /root/vm-extra.sh; extra_status=$?
	  echo "$extra_status" > "$R/extra.exit"; exit 0
	) 2>&1 | tee "$R/extra.out"
	echo "EXTRA_SCRIPT_STATUS=$(cat "$R/extra.exit")"
	echo EXTRA_SCRIPT_END
fi
# --- reroot, before (REROOT=1; tests/vm-provider-reroot.sh runs this block)
if [ "$REROOT" = 1 ] && [ "$rerooted" = no ]; then
	if [ "$(cat "$R/extra.exit" 2>/dev/null)" = 0 ]; then
		mv "$R/extra.out" "$R/extra.before.out"
		tar -cf /var/db/vm-provider-reroot.tar -C /tmp kyua-results
		sync
		echo REROOT_BEGIN
		kenv -u capability_plane
		kenv init_path=/sbin/capsule
		reboot -r
		# reboot -r kills this shell; reaching here is a failure.
		sleep 600
		echo "REROOT_FAIL: reboot -r returned"
	else
		echo "REROOT_FAIL: the extra script failed before the reroot"
	fi
fi
# --- end of the reroot
# The scratch disk (SCRATCH_DISK=1): name it in storage_test's input.
if [ "$SCRATCH_DISK" = 1 ]; then
	sd=
	for d in $(sysctl -n kern.disks); do
		[ "$(diskinfo -s "/dev/$d" 2>/dev/null)" = kyua-scratch ] && sd=/dev/$d
	done
	if [ -n "$sd" ] && [ -d /usr/tests/usr.sbin/capsule ]; then
		printf '%s\n' "$sd" > /usr/tests/usr.sbin/capsule/scratch-device
		echo "SCRATCH_DISK=$sd"
	else
		echo "SCRATCH_DISK_MISSING: no kyua-scratch disk or no usr.sbin/capsule tests"
	fi
fi
echo "ROOT_DF_BEFORE: $(df -k / | awk 'NR == 2 { print $2 "K total, " $4 "K free" }')"
cd /usr/tests
suites=$(cat /root/kyua-planeon.suites)
vars=; for v in $KYUA_VARS; do vars="$vars -v $v"; done
# Preserve test progress on the serial console as well as the results disk.
# Suite failures are summarized below; they must not prevent artifact export.
# Preserve the actual test status across tee without depending on pipefail.
{
    test_status=0
    # Verified file-handle lifetime cases require a disk-backed workdir.
    # Keep /tmp as tmpfs for cases that explicitly exercise that filesystem.
    TMPDIR=/var/tmp kyua -v parallelism="$PARALLELISM" $vars test -r "$R/results.db" $suites 2>&1 || test_status=$?
    printf '%s\n' "$test_status" > "$R/kyua-test.status"
} | tee "$R/kyua-test.out" || true
echo "KYUA_TEST_STATUS=$(cat "$R/kyua-test.status")"
kyua report -r "$R/results.db" --verbose > "$R/report-verbose.txt" 2>&1 || true
kyua report-junit -r "$R/results.db" --output="$R/results.junit.xml" 2>/dev/null || true
for kind in failed broken skipped; do
	echo "KYUA_${kind}_LIST_BEGIN" | tr a-z A-Z
	kyua report -r "$R/results.db" --results-filter "$kind" 2>&1 | grep -E " -> +$kind" || true
	echo "KYUA_${kind}_LIST_END" | tr a-z A-Z
done
echo KYUA_SKIP_REASONS_BEGIN
grep -o 'skipped: .*' "$R/kyua-test.out" | sed -e 's/ *\[[0-9.]*s\]$//' | sort | uniq -c | sort -rn
echo KYUA_SKIP_REASONS_END
kyua report -r "$R/results.db" --verbose --results-filter broken,failed 2>&1 | head -n 4000
cp /var/log/capability.log /var/log/messages "$R/" 2>/dev/null || true
dmesg -a > "$R/dmesg.txt" 2>&1 || true
echo "KYUA_SUMMARY: $(tail -n 1 "$R/kyua-test.out")"
echo "ROOT_DF_AFTER: $(df -k / | awk 'NR == 2 { print $2 "K total, " $4 "K free" }')"
# The ledger's knobs again, after the suites, in tier.txt.
{
	echo "after-suites:"
	for k in $TEST_KNOBS; do echo "knob $k=$(sysctl -n "$k" 2>/dev/null || echo absent)"; done
} >> "$R/tier.txt"
sed -n '/^after-suites:$/,$s/^/TIER_INFO: /p' "$R/tier.txt"
# The stack tier must have given its stacks test issuers, and freed them.
if [ "$stack_tier" = yes ]; then
	i=0
	while [ "$(sysctl -n kern.mac_capability.test_issuers_live)" -ne 0 ] && [ "$i" -lt 50 ]; do
		i=$((i + 1)); sleep 0.1
	done
	after=$(sysctl -n kern.mac_capability.test_issuers)
	live=$(sysctl -n kern.mac_capability.test_issuers_live)
	echo "STACK_TIER: test issuers created=$((after - stack_issuers_before)) live=$live state=$(sysctl -n kern.mac_capability.test_issuer_state)" |
	    tee -a "$R/tier.txt"
	case " $(cat /root/kyua-planeon.suites) " in
	*" usr.sbin/switchboard"*|*" usr.sbin/capsule"*|*" lib/libservice"*)
		[ "$after" -gt "$stack_issuers_before" ] ||
		    echo "STACK_TIER_FAIL: stack suites ran and no test issuer was created" ;;
	esac
	[ "$live" -eq 0 ] || echo "NOTE: $live test issuers still alive after the suites"
fi
# Results disk: only the explicitly identified second disk is written.
if [ "$(geom disk list vtbd1 2>/dev/null | awk '/ident:/ {print $2}')" = kyua-results ]; then
	tar -cf /dev/vtbd1 -C /tmp kyua-results && echo KYUA_RESULTS_DISK_WRITTEN
fi
sync
echo KYUA_VM_DONE
if [ "$PLANE_OFF" = 1 ] && [ "$rerooted" = no ]; then shutdown -p now; else
/usr/sbin/capsulectl poweroff || { echo PLANEON_CAPSULECTL_POWEROFF_FAILED; shutdown -p now; }
fi
EOF
sh -n "$x/kyua-planeon.sh" || die "generated guest script has a syntax error"

# --------------------------------------------------------------- manifest ---
over='boot/loader.conf boot/loader.conf.local etc/fstab etc/rc.conf etc/rc.local etc/ttys etc/gettytab root/.profile root/.zprofile root/kyua-planeon.sh root/kyua-planeon.suites root/vm-extra.sh'
[ -z "$sysctl_write" ] || over="$over $sysctl_conf"
re=$(for p in $over; do printf '%s|' "$p"; done | sed -e 's/|$//' -e 's/\./\\./g')
{
	echo '#mtree 2.0'
	grep -v '^#' "$stage/METALOG" | grep -vE "^\./($re)( |\$)"
	m() { echo "./$1 type=file uname=root gname=wheel mode=$2 contents=$x/$3"; }
	m boot/loader.conf 0644 loader.conf
	m boot/loader.conf.local 0644 loader.conf.local
	m etc/fstab 0644 fstab
	m etc/rc.conf 0644 rc.conf
	m etc/rc.local 0644 rc.local
	m etc/ttys 0644 ttys
	m etc/gettytab 0644 gettytab
	m root/.profile 0644 profile
	m root/.zprofile 0644 zprofile
	m root/kyua-planeon.sh 0555 kyua-planeon.sh
	m root/kyua-planeon.suites 0444 suites
	m root/vm-extra.sh 0555 extra.sh
	[ -z "$sysctl_write" ] || m "$sysctl_conf" 0644 sysctl.conf
	# A stage has /usr/src and /usr/obj but no ports mount point.
	[ -z "$ports_image" ] || echo "./usr/obj/5BSD-ports type=dir uname=root gname=wheel mode=0755"
	if [ -n "$src_image" ]; then
		for d in usr/obj/usr usr/obj/usr/src usr/obj/usr/src/repo; do
			echo "./$d type=dir uname=root gname=wheel mode=0755"
		done
	fi
	if [ -n "$extra_dir" ]; then
		echo "./root/vm-extra.d type=dir uname=root gname=wheel mode=0755"
		for f in "$extra_dir"/*; do
			[ -f "$f" ] || continue
			b=$(basename "$f")
			case $b in *[!A-Za-z0-9_.-]*) die "EXTRA_DIR file name: $b";; esac
			echo "./root/vm-extra.d/$b type=file uname=root gname=wheel mode=0555 contents=$(cd "$extra_dir" && pwd)/$b"
		done
	fi
	if [ -n "$linux_compat_dir" ]; then
		# Directories, symlinks and files of the overlay, modes kept;
		# the mount points for linprocfs and linsysfs.
		echo "./compat type=dir uname=root gname=wheel mode=0755"
		(cd "$linux_compat_dir" && find compat/linux -print | env -i LC_ALL=C sort) |
		while read -r p; do
			mode=$(stat -f %Lp "$linux_compat_dir/$p")
			if [ -L "$linux_compat_dir/$p" ]; then
				echo "./$p type=link uname=root gname=wheel mode=0755 link=$(readlink "$linux_compat_dir/$p")"
			elif [ -d "$linux_compat_dir/$p" ]; then
				echo "./$p type=dir uname=root gname=wheel mode=$mode"
			elif [ -f "$linux_compat_dir/$p" ]; then
				echo "./$p type=file uname=root gname=wheel mode=$mode contents=$linux_compat_dir/$p"
			fi
		done
		echo "./compat/linux/proc type=dir uname=root gname=wheel mode=0555"
		echo "./compat/linux/sys type=dir uname=root gname=wheel mode=0555"
	fi
} | awk 'NR == 1 { print; next } NF { print }' > "$work/METALOG.raw"
# Keep one record per path (makefs rejects duplicates in manifest mode); the
# last record wins: signing can update executable sizes after installation.
{ head -n 1 "$work/METALOG.raw"; tail -n +2 "$work/METALOG.raw" | awk '{ record[$1] = $0 } END { for (path in record) print record[path] }' |
    env -i LC_ALL=C sort -k1,1; } > "$work/METALOG"
for p in $over; do
	n=$(grep -c "^\./$p " "$work/METALOG" || true)
	[ "$n" = 1 ] || die "overlay record for $p appears $n times"
done

# ------------------------------------------------------------------ image ---
# Manifest mode: makefs resolves plain records relative to the cwd (the stage)
# and overlay records through contents=, so the stage is never written.
if [ "$root_fs" = zfs ]; then
(cd "$stage" && makefs -t zfs -s "$root_size" -o poolname=kyuaroot -o bootfs=kyuaroot \
    -o rootpath=/ "$work/root.ufs" "$work/METALOG") > "$work/makefs.log" 2>&1 ||
    { tail -n 20 "$work/makefs.log" >&2; die "makefs failed"; }
mkimg -s gpt -f raw -b "$stage/boot/pmbr" -p "freebsd-boot:=$stage/boot/gptzfsboot" \
    -p "freebsd-zfs:=$work/root.ufs" -o "$work/guest.img"
else
(cd "$stage" && makefs -t ffs -B little -s "$root_size" -o version=2,softupdates=1,label=root \
    "$work/root.ufs" "$work/METALOG") > "$work/makefs.log" 2>&1 ||
    { tail -n 20 "$work/makefs.log" >&2; die "makefs failed"; }
mkimg -s gpt -f raw -b "$stage/boot/pmbr" -p "freebsd-boot:=$stage/boot/gptboot" \
    -p "freebsd-ufs:=$work/root.ufs" -o "$work/guest.img"
fi
rm -f "$work/root.ufs"
truncate -s 512m "$work/results.img"
[ "$scratch_disk" = 0 ] || truncate -s 1g "$work/scratch.img"
echo "image: $work/guest.img"
if [ "${DRYRUN:-0}" = 1 ]; then echo DRYRUN_IMAGE_OK; exit 0; fi

# ------------------------------------------------------------------- boot ---
log=$work/serial.log
qmp=$work/qmp.sock
cat > "$work/qmp-events.py" <<'EOF'
import json, socket, sys, time
path, out = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
deadline = time.monotonic() + 30
while True:
    try:
        s.connect(path); break
    except OSError:
        if time.monotonic() > deadline: sys.exit(1)
        time.sleep(0.2)
buf = b''
with open(out, 'w') as f:
    while True:
        d = s.recv(65536)
        if not d: break
        buf += d
        while b'\n' in buf:
            line, buf = buf.split(b'\n', 1)
            if not line.strip(): continue
            msg = json.loads(line)
            f.write(json.dumps(msg) + '\n'); f.flush()
            if 'QMP' in msg: s.sendall(b'{"execute":"qmp_capabilities"}\r\n')
EOF
# SINGLE_USER_SHELL needs console input: a socket chardev that still logs
# everything the guest prints to the serial log.
serial_args="-serial file:$log"
console_sock=$work/console.sock
[ -z "${SINGLE_USER_SHELL:-}" ] || serial_args="-chardev socket,id=con0,path=$console_sock,server=on,wait=off,logfile=$log,logappend=on -serial chardev:con0"
set -- "$qemu" -L "$qemu_data" -accel tcg,thread=multi -machine q35 -cpu max \
    -m "$mem" -smp "$cpus" \
    -drive "file=$work/guest.img,format=raw,if=none,id=root,snapshot=on" \
    -device virtio-blk-pci,drive=root,bootindex=1 \
    -drive "file=$work/results.img,format=raw,if=none,id=results" \
    -device virtio-blk-pci,drive=results,serial=kyua-results \
    -netdev hubport,id=n0,hubid=0 -device virtio-net-pci,netdev=n0 \
    -display none -monitor none $serial_args \
    -qmp "unix:$qmp,server=on,wait=off"
[ -z "$src_image" ] || set -- "$@" \
    -drive "file=$src_image,format=raw,if=none,id=src,readonly=on" \
    -device virtio-blk-pci,drive=src,serial=usr-src
[ -z "$ports_image" ] || set -- "$@" \
    -drive "file=$ports_image,format=raw,if=none,id=ports,readonly=on" \
    -device virtio-blk-pci,drive=ports,serial=usr-ports
[ "$scratch_disk" = 0 ] || set -- "$@" \
    -drive "file=$work/scratch.img,format=raw,if=none,id=scratch" \
    -device virtio-blk-pci,drive=scratch,serial=kyua-scratch
printf '%s\n' "$@" > "$work/command.txt"
# The monitor watches this file for writes: it exists before QEMU starts
# (QEMU opens it without replacing it).
: > "$log"
"$@" > "$work/qemu.log" 2>&1 &
qpid=$!
echo "$qpid" > "$work/qemu.pid"
python3.12 "$work/qmp-events.py" "$qmp" "$work/qmp-events.jsonl" 2>"$work/qmp.err" &
mpid=$!
end=$(( $(date +%s) + timeout )) forced=0
fatal='panic:|Fatal trap|entering recovery|Enter full pathname of shell|mountroot>|Going nowhere without my init|could not quiesce init|init died'
# SINGLE_USER_SHELL: the run expects PID 1 to enter single-user once; the
# monitor answers the shell prompt with this guest path instead of stopping.
[ -z "${SINGLE_USER_SHELL:-}" ] ||
	fatal='panic:|Fatal trap|mountroot>|Going nowhere without my init|could not quiesce init|init died'
# A lock order reversal stops the run unless it matches known-lor.txt (a
# recorded false positive, reported as KNOWN_LOR) or FATAL_LOR=no, which a
# comparison sweep sets and then reads the reversals from the serial log.
known_lor=$(dirname "$0")/known-lor.txt
monitor=$(dirname "$0")/vm-monitor.py
unknown_lor() {
	[ "${FATAL_LOR:-yes}" = no ] && return 1
	grep -aq 'lock order reversal' "$log" 2>/dev/null || return 1
	ul=0; python3.12 -I "$monitor" --has-unknown-lor "$log" "$known_lor" || ul=$?
	case $ul in
	0)	return 0 ;;
	1)	return 1 ;;
	*)	echo "vm-monitor could not classify the reversals (exit $ul): counted as unknown"
		return 0 ;;
	esac
}
# --- monitor (tests/vm-provider-kill-after-exit.sh runs this block)
# vm-monitor.py waits on QEMU's exit, the serial log's writes and the
# deadline (one kqueue, no polling), stops QEMU on a fatal console line or
# an unknown reversal (after a short grace, unless the guest exits first)
# or at the deadline, and returns once QEMU has exited: 0 by itself, 3
# stopped for a problem, 4 at the deadline, 5 gone before it could be
# watched (not clean: nothing was checked live).  Anything else is the monitor
# failing; QEMU is then stopped here so the run still ends with its
# results and verdict.
if [ -n "${SINGLE_USER_SHELL:-}" ]; then
	python3.12 -I "$monitor" --pid "$qpid" --log "$log" --deadline "$end" \
	    --fatal "$fatal" --known "$known_lor" --fatal-lor "${FATAL_LOR:-yes}" \
	    --answer 'Enter full pathname of shell.*: $' \
	    --answer-text "$SINGLE_USER_SHELL" --console "$console_sock" \
	    > "$work/monitor.out" &
else
	python3.12 -I "$monitor" --pid "$qpid" --log "$log" --deadline "$end" \
	    --fatal "$fatal" --known "$known_lor" --fatal-lor "${FATAL_LOR:-yes}" &
fi
wpid=$!
mrc=0; wait "$wpid" || mrc=$?
case $mrc in
0)	;;
3|4|5)	forced=1 ;;
*)	echo "vm-monitor failed (exit $mrc): stopping qemu"; forced=1
	kill "$qpid" 2>/dev/null || echo "qemu had already exited" ;;
esac
rc=0; wait "$qpid" 2>/dev/null || rc=$?
[ -z "${SINGLE_USER_SHELL:-}" ] || cat "$work/monitor.out"
# --- end of the monitor
n=$(grep -ac 'lock order reversal' "$log" 2>/dev/null || true)
# --- LOR verdict (tests/vm-provider-known-lor.sh runs this block)
# The monitor classifies only complete reports while QEMU runs: one printed
# just before the guest powered off is decided here, on the whole log.
lor_unknown=0
if unknown_lor; then
	lor_unknown=1
	echo "UNKNOWN_LOR (a reversal matches no known-lor.txt entry; see the serial log)"
elif [ "${n:-0}" -gt 0 ] && [ "${FATAL_LOR:-yes}" != no ]; then
	echo "KNOWN_LOR=$n (matched known-lor.txt; see the serial log)"
fi
# --- end of the LOR verdict
wait "$mpid" 2>/dev/null || true
mkdir -p "$work/results"
bsdtar -xf "$work/results.img" -C "$work/results" 2>/dev/null || echo "results disk: no archive"
guest_off=0
python3.12 -c 'import json,sys
ev=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]
sys.exit(0 if any(e.get("event")=="SHUTDOWN" and e.get("data",{}).get("guest") is True and e["data"].get("reason")=="guest-shutdown" for e in ev) else 1)' "$work/qmp-events.jsonl" 2>/dev/null && guest_off=1
# --- stack-tier verdict (tests/vm-provider-stack-tier-verdict.sh runs this block)
# STACK_TIER=1 also needs the results disk's tier.txt, which tar writes whole,
# to show the tier met and its test issuers created and all freed: a kernel
# message landing mid-line on the console can hide a STACK_TIER_FAIL line.
stack_tier_met() {
	[ "$stack_tier_request" = 1 ] || return 0
	t=$work/results/kyua-results/tier.txt
	[ -f "$t" ] && grep -qx 'stack-tier=yes' "$t" &&
	    awk '$1 == "STACK_TIER:" && $4 ~ /^created=[0-9]+$/ && $5 ~ /^live=[0-9]+$/ {
		split($4, c, "="); split($5, l, "=")
		ok = (c[2] + 0 > 0 && l[2] + 0 == 0)
	    } END { exit !ok }' "$t"
}
# --- end of the stack-tier verdict
# SINGLE_USER_SHELL: the prompt was answered (once: a second prompt stops the
# run) and the single-user shell reported its own checks passed.
single_user_passed() {
	grep -qx CONSOLE_ANSWERED "$work/monitor.out" 2>/dev/null &&
	    LC_ALL=C tr -d '\r' < "$log" | grep -aqx 'SINGLE_USER_SHELL_PASS'
}
verdict=VM_NOT_CLEAN
if [ $forced = 0 ] && [ $lor_unknown = 0 ] && [ $rc = 0 ] && [ $guest_off = 1 ] && stack_tier_met &&
    [ "$(cat "$work/results/kyua-results/kyua-test.status" 2>/dev/null)" = 0 ] &&
    LC_ALL=C tr -d '\r' < "$log" | grep -aqx 'KYUA_VM_DONE' &&
    ! LC_ALL=C tr -d '\r' < "$log" | grep -aq '^STACK_TIER_FAIL' &&
    [ "$(LC_ALL=C tr -d '\r' < "$log" | grep -acx 'TEST_KERNEL_PROOF_PASS')" = 1 ] &&
    ! LC_ALL=C tr -d '\r' < "$log" | grep -aq '^TEST_KERNEL_PROOF_FAIL' &&
    { [ "$plane_off" = 1 ] && LC_ALL=C tr -d '\r' < "$log" | grep -aqx 'PLANEOFF_READY' ||
      { LC_ALL=C tr -d '\r' < "$log" | grep -aqx 'PLANEON_GATE_PASS' &&
        LC_ALL=C tr -d '\r' < "$log" | grep -aqx 'BSDTIME_LIFECYCLE_PASS'; }; } &&
    { [ -z "$extra_script" ] ||
      [ "$(cat "$work/results/kyua-results/extra.exit" 2>/dev/null)" = 0 ]; } &&
    { [ "$reroot" = 0 ] || { LC_ALL=C tr -d '\r' < "$log" | grep -aq '^REROOT_AFTER: pid1=capsule ' &&
      ! LC_ALL=C tr -d '\r' < "$log" | grep -aq '^REROOT_FAIL'; }; } &&
    { [ -z "${SINGLE_USER_SHELL:-}" ] || single_user_passed; } &&
    grep -aq 'Powering system off' "$log" && ! grep -aqE "$fatal" "$log"; then
	verdict=VM_CLEAN
fi
echo "qemu_exit=$rc forced=$forced guest_poweroff=$guest_off"
LC_ALL=C tr -d '\r' < "$log" | grep -aE '^(TIER_INFO: (KERNEL_TIER|TEST_KERNEL|stack-tier)=|STACK_TIER|REROOT_|TEST_KERNEL_PROOF|PLANEON_GATE|PLANEOFF|KYUA_SUMMARY|PLANEON_PID1|PLANEON_ISOLATION|BSDTIME)' || true
nskip=$(LC_ALL=C tr -d '\r' < "$log" | sed -n '/^KYUA_SKIPPED_LIST_BEGIN$/,/^KYUA_SKIPPED_LIST_END$/p' | grep -c ' -> ' || true)
echo "skipped=$nskip (a skip in a plane-on suite is not a pass; see KYUA_SKIPPED_LIST in $log)"
# Cases that named the tier they belong to: the run is not complete without
# a run of the same stage and suites in that tier.
for token in DEFERRED_ENFORCED_TIER DEFERRED_PLANEOFF_TIER DEFERRED_DEVICE_TIER \
    DEFERRED_STACK_TIER DEFERRED_PID1_ONLY DEFERRED_SOURCE_TIER \
    DEFERRED_GUEST_SETUP "configuration property 'authority_anchor'"; do
	ndefer=$(LC_ALL=C tr -d '\r' < "$log" | sed -n '/^KYUA_SKIPPED_LIST_BEGIN$/,/^KYUA_SKIPPED_LIST_END$/p' | grep -c "$token" || true)
	[ "$ndefer" -eq 0 ] || case $token in
	DEFERRED_ENFORCED_TIER)
		echo "DEFERRED_TO_ENFORCED_TIER=$ndefer (run PLANE_OFF=1 with the same stage and suites; not a pass)";;
	DEFERRED_PLANEOFF_TIER)
		echo "DEFERRED_TO_PLANEOFF_TIER=$ndefer (test-local stacks: run PLANE_OFF=1, and their unit cases on the stack tier; not a pass)";;
	DEFERRED_STACK_TIER)
		echo "DEFERRED_TO_STACK_TIER=$ndefer (run on GENERIC-TEST with KERNEL_TIER=test PLANE_OFF=1 and kern.mac_capability.test_issuer=1; not a pass)";;
	DEFERRED_PID1_ONLY)
		echo "DEFERRED_PID1_ONLY=$ndefer (they need the PID 1 Capsule; no tier runs them; not a pass)";;
	DEFERRED_SOURCE_TIER)
		echo "DEFERRED_TO_SOURCE_TIER=$ndefer (they read /usr/src: run with SRC_IMAGE; not a pass)";;
	DEFERRED_GUEST_SETUP)
		echo "DEFERRED_GUEST_SETUP=$ndefer (they need a guest setup no tier provides yet, such as a scratch disk or a stopped devd; not a pass)";;
	"configuration property 'authority_anchor'")
		echo "DEFERRED_TO_ANCHOR_RUN=$ndefer (they anchor the boot: run alone with KYUA_VARS=test_suites.FreeBSD.authority_anchor=1; not a pass)";;
	*)
		echo "DEFERRED_TO_DEVICE_TIER=$ndefer (run without ISOLATION_ENFORCE=1 with the same stage and suites; not a pass)";;
	esac
done
# A case kyua skipped for a module that is not loaded did not run: the stage
# or the loader configuration is incomplete, and the run is not clean.
nkmod=$(LC_ALL=C tr -d '\r' < "$log" | sed -n '/^KYUA_SKIPPED_LIST_BEGIN$/,/^KYUA_SKIPPED_LIST_END$/p' | grep -c 'Required kmods are not loaded' || true)
if [ "$nkmod" -ne 0 ]; then
	echo "KMOD_SKIPPED=$nkmod (required kernel modules not loaded; not a pass)"
	verdict=VM_NOT_CLEAN
fi
echo "$verdict"
[ "$verdict" = VM_CLEAN ]
