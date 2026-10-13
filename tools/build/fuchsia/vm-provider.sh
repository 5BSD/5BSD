#!/bin/sh
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
# Environment: CPUS (default 8), MEM_MB (8192), PARALLELISM (kyua, default 1),
#   GATE_TIMEOUT (guest seconds to wait for provider convergence, 600),
#   REQUIRE_UNITS (space-separated SwitchBoard labels that must be "running"
#   before tests start; default: the twelve core providers that
#   software-application-guest.sh requires), QEMU, QEMU_DATA,
#   DRYRUN=1 (build and check the image, do not boot), LOADER_EXTRA (extra
#   loader.conf lines).
#   ISOLATION_ENFORCE=1 retains production device isolation for deployment
#   checks; the default 0 permits raw-device provider test fixtures.
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

usage() { sed -n '2,/^set -eu/p' "$0" | sed -e '/^set -eu/d' -e 's/^# \{0,1\}//' >&2; exit 64; }
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
plane_off=${PLANE_OFF:-0}
isolation=${ISOLATION_ENFORCE:-0}
case "$isolation" in 0|1) ;; *) echo "ISOLATION_ENFORCE must be 0 or 1" >&2; exit 64;; esac
extra_script=${EXTRA_SCRIPT:-}
[ -z "$extra_script" ] || [ -f "$extra_script" ] || die "no such EXTRA_SCRIPT: $extra_script"
extra_dir=${EXTRA_DIR:-}
[ -z "$extra_dir" ] || [ -d "$extra_dir" ] || die "no such EXTRA_DIR: $extra_dir"
cpus=${CPUS:-4} mem=${MEM_MB:-8192} par=${PARALLELISM:-1} gate=${GATE_TIMEOUT:-600}
units=${REQUIRE_UNITS:-system.Log/bsdlog system.Network/bsdnetwork system.Trace/bsdtrace system.Filesystem/bsdfilesystem system.Audit/bsdaudit system.Time/bsdtime system.SystemExtension/bsdextension system.Notify/bsdnotify system.Device/bsddevice system.Power/bsdpower system.Sysctl/bsdsysctl system.Crypto/bsdcrypto}

die() { echo "vm-provider: $*" >&2; exit 2; }
isnum() { case $1 in ''|*[!0-9]*) return 1;; esac; [ "$1" -gt 0 ]; }
for n in "$timeout" "$cpus" "$mem" "$par" "$gate"; do isnum "$n" || die "not a positive integer: $n"; done
case $suites in *[!A-Za-z0-9_./:\ -]*|'') die "suite list may only contain [A-Za-z0-9_./:-] and spaces";; esac
case $units in *[!A-Za-z0-9_./\ -]*) die "REQUIRE_UNITS has unexpected characters";; esac
case $kyua_vars in *[!A-Za-z0-9_.=\ -]*) die "KYUA_VARS has unexpected characters";; esac

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
[ -n "$qemu" ] || die "no runnable QEMU (set QEMU=)"
echo "qemu: $qemu ($("$qemu" --version | head -n 1))"
[ -d "$qemu_data" ] || die "no QEMU firmware dir $qemu_data"
[ ! -e "$work" ] || die "work dir exists: $work"
mkdir -p "$work"
work=$(cd "$work" && pwd)
[ ${#work} -le 80 ] || die "work path too long for the QMP UNIX socket: $work"

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
	# No Capsule claims the device with the plane off, so keep isolation
	# enforced: the isolation suites run in this tier and need it.
	sed -i '' '/^# Test mode:/,/^kern.mac_capability_isolation.enforce=/d' \
	    "$x/loader.conf"
	printf 'capability_plane="NO"\n' >> "$x/loader.conf"
	: > "$x/loader.conf.local"
fi
# LOADER_EXTRA: more loader.conf lines, e.g. dtraceall_load="YES".
[ -z "${LOADER_EXTRA:-}" ] || printf '%s\n' "$LOADER_EXTRA" >> "$x/loader.conf"
if [ -n "$extra_script" ]; then cp "$extra_script" "$x/extra.sh"; else : > "$x/extra.sh"; fi
cat > "$x/fstab" <<'EOF'
/dev/vtbd0p2	/	ufs	rw	1	1
tmpfs		/tmp	tmpfs	rw,mode=1777	0	0
tmpfs		/Capabilities/Run	tmpfs	rw,mode=0700	0	0
EOF
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
case "$-" in *i*) ;; *) return ;; esac
if [ "$(tty)" = /dev/ttyu0 ] && [ ! -e /tmp/.kyua-planeon-started ]; then
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
if [[ -o interactive ]] && [ "$(tty)" = /dev/ttyu0 ] && [ ! -e /tmp/.kyua-planeon-started ]; then
	: > /tmp/.kyua-planeon-started
	sh /root/kyua-planeon.sh
	[ $? = 99 ] && exit
fi
EOF
} > "$x/zprofile"
printf '%s\n' "$suites" > "$x/suites"
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
EOF
cat >> "$x/kyua-planeon.sh" <<'EOF'
R=/tmp/kyua-results
mkdir -p "$R"
echo KYUA_PLANEON_START
if [ "$PLANE_OFF" = 1 ]; then
echo "PLANEOFF_PID1=$(ps -o comm= -p 1 | tr -d ' ')"
echo PLANEOFF_READY
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
if [ -s /root/vm-extra.sh ]; then
	echo EXTRA_SCRIPT_BEGIN
	( set +e; sh /root/vm-extra.sh; extra_status=$?
	  echo "$extra_status" > "$R/extra.exit"; exit 0
	) 2>&1 | tee "$R/extra.out"
	echo "EXTRA_SCRIPT_STATUS=$(cat "$R/extra.exit")"
	echo EXTRA_SCRIPT_END
fi
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
# Results disk: only the explicitly identified second disk is written.
if [ "$(geom disk list vtbd1 2>/dev/null | awk '/ident:/ {print $2}')" = kyua-results ]; then
	tar -cf /dev/vtbd1 -C /tmp kyua-results && echo KYUA_RESULTS_DISK_WRITTEN
fi
sync
echo KYUA_VM_DONE
if [ "$PLANE_OFF" = 1 ]; then shutdown -p now; else
/usr/sbin/capsulectl poweroff || { echo PLANEON_CAPSULECTL_POWEROFF_FAILED; shutdown -p now; }
fi
EOF
sh -n "$x/kyua-planeon.sh" || die "generated guest script has a syntax error"

# --------------------------------------------------------------- manifest ---
over='boot/loader.conf boot/loader.conf.local etc/fstab etc/rc.conf etc/rc.local etc/ttys etc/gettytab root/.profile root/.zprofile root/kyua-planeon.sh root/kyua-planeon.suites root/vm-extra.sh'
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
	if [ -n "$extra_dir" ]; then
		echo "./root/vm-extra.d type=dir uname=root gname=wheel mode=0755"
		for f in "$extra_dir"/*; do
			[ -f "$f" ] || continue
			b=$(basename "$f")
			case $b in *[!A-Za-z0-9_.-]*) die "EXTRA_DIR file name: $b";; esac
			echo "./root/vm-extra.d/$b type=file uname=root gname=wheel mode=0555 contents=$(cd "$extra_dir" && pwd)/$b"
		done
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
(cd "$stage" && makefs -t ffs -B little -s 8g -o version=2,softupdates=1,label=root \
    "$work/root.ufs" "$work/METALOG") > "$work/makefs.log" 2>&1 ||
    { tail -n 20 "$work/makefs.log" >&2; die "makefs failed"; }
mkimg -s gpt -f raw -b "$stage/boot/pmbr" -p "freebsd-boot:=$stage/boot/gptboot" \
    -p "freebsd-ufs:=$work/root.ufs" -o "$work/guest.img"
rm -f "$work/root.ufs"
truncate -s 512m "$work/results.img"
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
set -- "$qemu" -L "$qemu_data" -accel tcg,thread=multi -machine q35 -cpu max \
    -m "$mem" -smp "$cpus" \
    -drive "file=$work/guest.img,format=raw,if=none,id=root,snapshot=on" \
    -device virtio-blk-pci,drive=root,bootindex=1 \
    -drive "file=$work/results.img,format=raw,if=none,id=results" \
    -device virtio-blk-pci,drive=results,serial=kyua-results \
    -netdev hubport,id=n0,hubid=0 -device virtio-net-pci,netdev=n0 \
    -display none -monitor none -serial "file:$log" \
    -qmp "unix:$qmp,server=on,wait=off"
printf '%s\n' "$@" > "$work/command.txt"
"$@" > "$work/qemu.log" 2>&1 &
qpid=$!
echo "$qpid" > "$work/qemu.pid"
python3.12 "$work/qmp-events.py" "$qmp" "$work/qmp-events.jsonl" 2>"$work/qmp.err" &
mpid=$!
end=$(( $(date +%s) + timeout )) forced=0
fatal='panic:|Fatal trap|lock order reversal|entering recovery|Enter full pathname of shell|mountroot>|Going nowhere without my init|could not quiesce init|init died'
while kill -0 "$qpid" 2>/dev/null; do
	if grep -aqE "$fatal" "$log" 2>/dev/null; then
		echo "KERNEL/INIT PROBLEM in serial log"; sleep 5; forced=1; kill "$qpid"; break
	fi
	if [ "$(date +%s)" -ge "$end" ]; then echo TIMEOUT; forced=1; kill "$qpid"; break; fi
	sleep 10
done
rc=0; wait "$qpid" 2>/dev/null || rc=$?
wait "$mpid" 2>/dev/null || true
mkdir -p "$work/results"
bsdtar -xf "$work/results.img" -C "$work/results" 2>/dev/null || echo "results disk: no archive"
guest_off=0
python3.12 -c 'import json,sys
ev=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]
sys.exit(0 if any(e.get("event")=="SHUTDOWN" and e.get("data",{}).get("guest") is True and e["data"].get("reason")=="guest-shutdown" for e in ev) else 1)' "$work/qmp-events.jsonl" 2>/dev/null && guest_off=1
verdict=VM_NOT_CLEAN
if [ $forced = 0 ] && [ $rc = 0 ] && [ $guest_off = 1 ] &&
    [ "$(cat "$work/results/kyua-results/kyua-test.status" 2>/dev/null)" = 0 ] &&
    tr -d '\r' < "$log" | grep -aqx 'KYUA_VM_DONE' &&
    { [ "$plane_off" = 1 ] && tr -d '\r' < "$log" | grep -aqx 'PLANEOFF_READY' ||
      { tr -d '\r' < "$log" | grep -aqx 'PLANEON_GATE_PASS' &&
        tr -d '\r' < "$log" | grep -aqx 'BSDTIME_LIFECYCLE_PASS'; }; } &&
    { [ -z "$extra_script" ] ||
      [ "$(cat "$work/results/kyua-results/extra.exit" 2>/dev/null)" = 0 ]; } &&
    grep -aq 'Powering system off' "$log" && ! grep -aqE "$fatal" "$log"; then
	verdict=VM_CLEAN
fi
echo "qemu_exit=$rc forced=$forced guest_poweroff=$guest_off"
tr -d '\r' < "$log" | grep -aE '^(PLANEON_GATE|PLANEOFF|KYUA_SUMMARY|PLANEON_PID1|PLANEON_ISOLATION|BSDTIME)' || true
nskip=$(tr -d '\r' < "$log" | sed -n '/^KYUA_SKIPPED_LIST_BEGIN$/,/^KYUA_SKIPPED_LIST_END$/p' | grep -c ' -> ' || true)
echo "skipped=$nskip (a skip in a plane-on suite is not a pass; see KYUA_SKIPPED_LIST in $log)"
echo "$verdict"
[ "$verdict" = VM_CLEAN ]
