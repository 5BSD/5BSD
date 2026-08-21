#!/bin/sh
# Aggregate, fail-closed WASPNest qualification entry point.
set -eu

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
testroot=${WASPNEST_TESTROOT:-$(CDPATH= cd -- "$script_dir/.." && pwd)}
srctop=${SRCTOP:-/usr/src}
host_arch=${WASPNEST_HOST_ARCH:-$(uname -m)}
device=$testroot/sys/kern/vsock_device_harness
rx=$testroot/sys/kern/vsock_rx_harness
e2e=$testroot/sys/kern/vsock_e2e
vmm=$testroot/sys/vmm
suite=$script_dir/waspnest-suite.tsv
nonvirtio=$script_dir/waspnest-nonvirtio-coverage.tsv
nonvirtio_validator=$script_dir/validate-nonvirtio-coverage
if [ ! -x "$nonvirtio_validator" ]; then
	nonvirtio_validator=$script_dir/validate-nonvirtio-coverage.sh
fi
completion_matrix=$script_dir/waspnest-completion-matrix.md
if [ ! -f "$completion_matrix" ]; then
	completion_matrix=$srctop/docs/waspnest-completion-matrix.md
fi

fail()
{
	echo "waspnest-test: $*" >&2
	exit 1
}

need_file()
{
	[ -f "$1" ] || fail "missing required file: $1"
}

need_exec()
{
	[ -x "$1" ] || fail "missing required executable: $1"
}

run_gate()
{
	echo "=== $1 ==="
	shift
	"$@"
}

require_privileged_payload()
{
	case ${WASPNEST_ALLOW_UNTRUSTED_SOURCE:-no} in
	no) ;;
	yes) return ;;
	*) fail "WASPNEST_ALLOW_UNTRUSTED_SOURCE must be yes or no" ;;
	esac
	resolved_script_dir=$(realpath "$script_dir") ||
	    fail "cannot resolve runner directory: $script_dir"
	resolved_testroot=$(realpath "$testroot") ||
	    fail "cannot resolve test root: $testroot"
	[ "$resolved_script_dir" = /usr/tests/waspnest ] &&
	    [ "$resolved_testroot" = /usr/tests ] ||
	    fail "root execution requires the installed /usr/tests payload; set WASPNEST_ALLOW_UNTRUSTED_SOURCE=yes only for a reviewed development tree"
}

require_payload()
{
	need_file "$suite"
	need_file "$device/virtio-1.4-requirements.tsv"
	need_file "$device/virtio-feature-activation.tsv"
	need_file "$device/virtio-nonstandard-interfaces.tsv"
	need_file "$vmm/vmx-nested-requirements.tsv"
	need_file "$vmm/vmx-nested-live-qualification.tsv"
	need_file "$vmm/vmx-nested-default-policy-live-qualification.tsv"
	need_file "$nonvirtio"
	need_exec "$e2e/run-waspnest-qualification.sh"
}

list_gates()
{
	need_file "$suite"
	awk -F '\t' 'NR == 1 { next }
	    { printf "%-18s %-16s %-20s root=%-3s %s\n", $1, $2, $3, $4, $6 }' \
	    "$suite"
}

validate_dispositions()
{
	awk -F '\t' '
	    NR == 1 || $0 ~ /^#/ { next }
	    $3 !~ /^(exercised|pending|driver-gap|not-applicable)$/ ||
	    $5 !~ /^(exercised|pending|driver-gap|not-applicable)$/ { exit 1 }
	' "$device/virtio-feature-activation.tsv" ||
	    fail "VirtIO activation ledger contains an unknown disposition"
	awk -F '\t' '
	    NR == 1 || $0 ~ /^#/ { next }
	    $3 !~ /^(exercised|pending|driver-gap|not-applicable)$/ ||
	    $5 !~ /^(exercised|pending|driver-gap|not-applicable)$/ { exit 1 }
	' "$vmm/vmx-nested-live-qualification.tsv" ||
	    fail "nested live ledger contains an unknown disposition"
	awk -F '\t' '
	    NR == 1 || $0 ~ /^#/ { next }
	    $3 !~ /^(exercised|pending|driver-gap|not-applicable)$/ ||
	    $5 !~ /^(exercised|pending|driver-gap|not-applicable)$/ { exit 1 }
	' "$vmm/vmx-nested-default-policy-live-qualification.tsv" ||
	    fail "nested default-policy ledger contains an unknown disposition"
	awk -F '\t' '
	    NR == 1 || $0 ~ /^#/ { next }
	    $4 !~ /^(exercised|pending|driver-gap|not-applicable|environment-dependent)$/ ||
	    $6 !~ /^(exercised|pending|driver-gap|not-applicable|environment-dependent)$/ ||
	    $8 !~ /^(exercised|pending|driver-gap|not-applicable|environment-dependent)$/ { exit 1 }
	' "$nonvirtio" ||
	    fail "non-VirtIO ledger contains an unknown disposition"
}

status()
{
	require_payload
	validate_dispositions
	awk -F '\t' '
	    NR > 1 && $0 !~ /^#/ { linux[$3]++; fivebsd[$5]++; rows++ }
	    END {
		printf "VirtIO activation rows: %d\n", rows
		n = split("exercised pending driver-gap not-applicable", order, " ")
		for (i = 1; i <= n; i++) if (linux[order[i]])
		    printf "  Linux %-24s %d\n", order[i], linux[order[i]]
		for (i = 1; i <= n; i++) if (fivebsd[order[i]])
		    printf "  5BSD  %-24s %d\n", order[i], fivebsd[order[i]]
	    }' "$device/virtio-feature-activation.tsv"
	awk -F '\t' '
	    NR > 1 && $0 !~ /^#/ { linux[$3]++; fivebsd[$5]++; rows++ }
	    END {
		printf "Nested live groups: %d\n", rows
		n = split("exercised pending driver-gap not-applicable", order, " ")
		for (i = 1; i <= n; i++) if (linux[order[i]])
		    printf "  Linux-L2 %-21s %d\n", order[i], linux[order[i]]
		for (i = 1; i <= n; i++) if (fivebsd[order[i]])
		    printf "  5BSD-L2  %-21s %d\n", order[i], fivebsd[order[i]]
	    }' "$vmm/vmx-nested-live-qualification.tsv"
	awk -F '\t' '
	    NR > 1 && $0 !~ /^#/ { linux[$3]++; fivebsd[$5]++; rows++ }
	    END {
		printf "Nested default-policy groups: %d\n", rows
		n = split("exercised pending driver-gap not-applicable", order, " ")
		for (i = 1; i <= n; i++) if (linux[order[i]])
		    printf "  Linux-L2 %-21s %d\n", order[i], linux[order[i]]
		for (i = 1; i <= n; i++) if (fivebsd[order[i]])
		    printf "  5BSD-L2  %-21s %d\n", order[i], fivebsd[order[i]]
	    }' "$vmm/vmx-nested-default-policy-live-qualification.tsv"
	awk -F '\t' '
	    NR > 1 && $0 !~ /^#/ { linux[$4]++; fivebsd[$6]++; checkpoint[$8]++; rows++ }
	    END {
		printf "Non-VirtIO device rows: %d\n", rows
		n = split("exercised pending driver-gap not-applicable environment-dependent", order, " ")
		for (i = 1; i <= n; i++) if (linux[order[i]])
		    printf "  Linux %-24s %d\n", order[i], linux[order[i]]
		for (i = 1; i <= n; i++) if (fivebsd[order[i]])
		    printf "  5BSD  %-24s %d\n", order[i], fivebsd[order[i]]
		for (i = 1; i <= n; i++) if (checkpoint[order[i]])
		    printf "  save/restore %-17s %d\n", order[i], checkpoint[order[i]]
	    }' "$nonvirtio"
}

audit()
{
	if [ "$(id -u)" -eq 0 ]; then
		require_privileged_payload
	fi
	require_payload
	[ -d "$srctop/sys" ] || fail "matching source tree not found: $srctop"
	need_exec "$device/validate-virtio-requirements.sh"
	need_exec "$device/validate-virtio-nonstandard-interfaces.sh"
	need_exec "$device/validate-virtio-snapshot-portability.sh"
	need_exec "$device/validate-waspnest-completion-matrix.sh"
	need_exec "$e2e/virtio-lab-selftest.sh"
	need_exec "$nonvirtio_validator"
	need_file "$completion_matrix"

	run_gate "VirtIO requirement/source/activation mapping" env SRCTOP="$srctop" \
	    sh "$device/validate-virtio-requirements.sh" \
	    "$device/virtio-1.4-requirements.tsv" "$device" "$srctop" \
	    "$device/virtio-feature-activation.tsv"
	run_gate "VirtIO implementation-defined interface inventory" env \
	    SRCTOP="$srctop" sh "$device/validate-virtio-nonstandard-interfaces.sh" \
	    "$device/virtio-nonstandard-interfaces.tsv" "$srctop"
	run_gate "Portable snapshot boundary" env SRCTOP="$srctop" \
	    sh "$device/validate-virtio-snapshot-portability.sh"
	case "$host_arch" in
	amd64)
		need_exec "$vmm/validate-vmx-nested-requirements.sh"
		need_exec "$vmm/validate-vmx-nested-public-headers.sh"
		need_exec "$vmm/vmx-nested-requirements-selftest.sh"
		need_exec "$vmm/vmx-nested-live-coverage-selftest.sh"
		run_gate "Nested VMX requirement/source/test mapping" env \
		    SRCTOP="$srctop" sh "$vmm/validate-vmx-nested-requirements.sh"
		run_gate "Nested VMX public headers" env SRCTOP="$srctop" \
		    sh "$vmm/validate-vmx-nested-public-headers.sh"
		run_gate "Nested VMX validator falsification" env SRCTOP="$srctop" \
		    sh "$vmm/vmx-nested-requirements-selftest.sh"
		run_gate "Nested VMX live-coverage validator" env SRCTOP="$srctop" \
		    sh "$vmm/vmx-nested-live-coverage-selftest.sh"
		;;
	*)
		echo "=== Nested VMX validation ==="
		echo "SKIP nested VMX is Intel amd64-only; host architecture is $host_arch"
		;;
	esac
	run_gate "WASPNest completion matrix" env SRCTOP="$srctop" \
	    sh "$device/validate-waspnest-completion-matrix.sh" \
	    "$completion_matrix" \
	    "$device/virtio-1.4-requirements.tsv" \
	    "$device/virtio-feature-activation.tsv" \
	    "$device/virtio-nonstandard-interfaces.tsv" \
	    "$vmm/vmx-nested-requirements.tsv" \
	    "$vmm/vmx-nested-live-qualification.tsv" \
	    "$vmm/vmx-nested-default-policy-live-qualification.tsv" \
	    "$vmm/vmx-nested-nonstandard-interfaces.tsv" \
	    "$vmm/vmx-startup-entry-edge-matrix.tsv"
	run_gate "VirtIO lab scheduler and failure semantics" \
	    sh "$e2e/virtio-lab-selftest.sh"
	run_gate "Non-VirtIO source and live-coverage inventory" env \
	    SRCTOP="$srctop" sh "$nonvirtio_validator" \
	    "$nonvirtio"
	echo "PASS WASPNest audit"
}

require_root()
{
	[ "$(id -u)" -eq 0 ] || fail "$1 requires root"
}

post_reboot()
{
	require_root post-reboot
	require_payload
	uname -v | grep -Fq 5BSD || fail "running kernel banner is not branded 5BSD"
	need_file /etc/os-release
	grep -Eq '^NAME=("?5BSD"?)$' /etc/os-release ||
	    fail "/etc/os-release NAME is not 5BSD"
	grep -Eq '^ID=("?5bsd"?)$' /etc/os-release ||
	    fail "/etc/os-release ID is not 5bsd"
	host=$(hostname -s)
	case $(printf '%s' "$host" | tr '[:upper:]' '[:lower:]') in
	freebsd|freebsd.*|'') fail "default/stale hostname remains $host" ;;
	esac
	if [ -n "${EXPECT_HOSTNAME:-}" ]; then
		[ "$host" = "$EXPECT_HOSTNAME" ] ||
		    fail "hostname $host does not match $EXPECT_HOSTNAME"
	fi
	pid1=$(ps -p 1 -o command=)
	pid1_comm=$(ps -p 1 -o comm= | tr -d '[:space:]')
	case "$pid1_comm" in
	oracle-init|oracled) ;;
	*) fail "PID 1 is not the Oracle init personality: $pid1" ;;
	esac
	need_exec /sbin/oracle-init
	need_exec /usr/sbin/oracled
	cmp -s /sbin/oracle-init /usr/sbin/oracled ||
	    fail "/sbin/oracle-init does not match the installed oracled binary"
	serviced_child=no
	for serviced_pid in $(pgrep -x serviced 2>/dev/null || true); do
		[ "$(ps -p "$serviced_pid" -o ppid= | tr -d '[:space:]')" = 1 ] &&
		    serviced_child=yes
	done
	[ "$serviced_child" = yes ] ||
	    fail "no serviced process is directly supervised by Oracle PID 1"
	kldstat -m vmm >/dev/null || fail "installed vmm module is not loaded"
	case $(uname -m) in
	amd64)
		if sysctl -n hw.vmm.vmx.initialized >/dev/null 2>&1; then
			[ "$(sysctl -n hw.vmm.vmx.initialized)" = 1 ] ||
			    fail "VMX backend is not initialized"
		elif ! sysctl -n hw.vmm.svm.features >/dev/null 2>&1; then
			fail "neither initialized VMX nor an SVM backend is available"
		fi
		;;
	esac
	need_exec /usr/sbin/bhyve
	need_exec /usr/sbin/bhyvectl
	if command -v freebsd-version >/dev/null 2>&1; then
		kernel_version=$(freebsd-version -k)
		user_version=$(freebsd-version -u)
		[ "$kernel_version" = "$user_version" ] ||
		    fail "kernel/world mismatch: kernel=$kernel_version world=$user_version"
	fi
	echo "PASS WASPNest post-reboot host gate: hostname=$host pid1=$pid1"
}

host_tests()
{
	require_root host
	require_privileged_payload
	post_reboot
	audit
	need_exec "$e2e/virtio-host-regression.sh"
	need_file "$device/Kyuafile"
	need_file "$rx/Kyuafile"
	need_file "$vmm/Kyuafile"
	run_gate "VM-free sanitizer and host regression" env \
	    RUN_PRIVILEGED_ATF=yes SRCTOP="$srctop" \
	    sh "$e2e/virtio-host-regression.sh"
	run_gate "bhyve device-model Kyua corpus" \
	    kyua test -k "$device/Kyuafile"
	run_gate "AF_VSOCK guest-transport Kyua corpus" \
	    kyua test -k "$rx/Kyuafile"
	run_gate "VMM, snapshot-session, dirty-log, startup, and nested model corpus" \
	    kyua test -k "$vmm/Kyuafile"
	echo "PASS WASPNest host gate"
}

campaign_pid=
campaign_completed=no
campaign_workdir=

campaign_running()
{
	[ -n "$campaign_pid" ] || return 1
	state=$(ps -p "$campaign_pid" -o state= 2>/dev/null | tr -d '[:space:]') ||
	    return 1
	case "$state" in
	''|Z*) return 1 ;;
	*) return 0 ;;
	esac
}

cancel_campaign()
{
	status=$1
	trap - HUP INT TERM
	if campaign_running; then
		# The direct child execs the lab manager.  Give its cleanup handlers a
		# bounded opportunity to stop cases, bhyve, TAPs, and bridges before
		# escalating.  The PID remains waitable, so it cannot be reused here.
		kill -TERM "$campaign_pid" 2>/dev/null || true
		i=0
		while campaign_running && [ "$i" -lt 30 ]; do
			sleep 1
			i=$((i + 1))
		done
		if campaign_running; then
			echo "waspnest-test: campaign cleanup exceeded 30s; forcing manager exit" >&2
			kill -KILL "$campaign_pid" 2>/dev/null || true
		fi
		wait "$campaign_pid" 2>/dev/null || true
	fi
	campaign_pid=
	echo "waspnest-test: interrupted; cancellation is not qualification evidence" >&2
	exit "$status"
}

run_campaign()
{
	trap 'cancel_campaign 129' HUP
	trap 'cancel_campaign 130' INT
	trap 'cancel_campaign 143' TERM
	"$e2e/run-waspnest-qualification.sh" &
	campaign_pid=$!
	if wait "$campaign_pid"; then
		status=0
		campaign_completed=yes
		campaign_workdir=${WORKDIR:-/tmp/virtio-qualification}
	else
		status=$?
	fi
	campaign_pid=
	trap - HUP INT TERM
	return "$status"
}

release_ready()
{
	require_payload
	validate_dispositions
	if [ "$campaign_completed" != yes ]; then
		[ -n "${WORKDIR:-}" ] ||
		    fail "standalone release-ready requires WORKDIR naming a completed content-bound campaign"
		campaign_workdir=$WORKDIR
	fi
	[ -n "$campaign_workdir" ] && [ -d "$campaign_workdir" ] ||
	    fail "current campaign workdir is unavailable"
	need_file "$campaign_workdir/run.config"
	need_file "$campaign_workdir/summary"
	need_file "$campaign_workdir/events.tsv"
	lab=$e2e/virtio-lab
	if [ ! -x "$lab" ]; then
		lab=$e2e/virtio-lab.lua
	fi
	need_exec "$lab"
	"$lab" verify-inputs --workdir "$campaign_workdir" >/dev/null ||
	    fail "current campaign inputs no longer match its recorded identities"
	grep -qx 'version=3' "$campaign_workdir/run.config" ||
	    fail "current campaign does not contain content-bound input identities"
	saved_profile=$(sed -n 's/^profile=//p' "$campaign_workdir/run.config")
	[ -n "$saved_profile" ] || fail "current campaign does not identify its profile"
	if [ -n "${PROFILE:-}" ]; then
		[ "$PROFILE" = "$saved_profile" ] ||
		    fail "requested release profile does not match current campaign"
	else
		PROFILE=$saved_profile
		export PROFILE
	fi
	grep -qx "profile=$PROFILE" \
	    "$campaign_workdir/run.config" ||
	    fail "current campaign profile does not match release profile"
	case_count=$(grep -c '^case=' "$campaign_workdir/run.config")
	passed=$(sed -n 's/^passed=//p' "$campaign_workdir/summary")
	failed=$(sed -n 's/^failed=//p' "$campaign_workdir/summary")
	blocked=$(sed -n 's/^blocked=//p' "$campaign_workdir/summary")
	total=$(sed -n 's/^total=//p' "$campaign_workdir/summary")
	case "$passed:$failed:$blocked:$total:$case_count" in
	*[!0-9:]*|*::*|:*|*:) fail "current campaign summary is malformed" ;;
	esac
	[ "$failed" -eq 0 ] && [ "$blocked" -eq 0 ] &&
	    [ "$passed" -eq "$total" ] && [ "$total" -eq "$case_count" ] ||
	    fail "current campaign is incomplete: passed=$passed failed=$failed blocked=$blocked total=$total selected=$case_count"
	for case_id in $(sed -n 's/^case=//p' "$campaign_workdir/run.config"); do
		[ -f "$campaign_workdir/status/$case_id" ] &&
		    [ "$(cat "$campaign_workdir/status/$case_id")" = 0 ] ||
		    fail "current campaign lacks a successful terminal result for $case_id"
	done
	if sysctl -n hw.vmm.vmx.initialized 2>/dev/null | grep -qx 1; then
		case ${PROFILE:-} in
		intel-qualification|full-qualification) ;;
		*) fail "Intel release qualification requires a profile containing nested and non-VirtIO live gates" ;;
		esac
	else
		case ${PROFILE:-} in
		qualification|full-qualification) ;;
		*) fail "release qualification requires a profile containing non-VirtIO live gates" ;;
		esac
	fi
	virtio_unresolved=$(awk -F '\t' 'NR > 1 && $0 !~ /^#/ {
	    if ($3 == "pending") n++
	    if ($5 == "pending") n++
	} END { print n + 0 }' "$device/virtio-feature-activation.tsv")
	require_nested=no
	case ${PROFILE:-} in
	intel-qualification|full-qualification|nested|nested-default)
		require_nested=yes
		;;
	'')
		if [ "$host_arch" = amd64 ] &&
		    sysctl -n hw.vmm.vmx.initialized 2>/dev/null | grep -qx 1; then
			require_nested=yes
		fi
		;;
	esac
	if [ "$require_nested" = yes ]; then
		nested_unresolved=$(awk -F '\t' 'NR > 1 && $0 !~ /^#/ {
		    if ($3 == "pending") n++
		    if ($5 == "pending") n++
		} END { print n + 0 }' "$vmm/vmx-nested-live-qualification.tsv")
		nested_default_unresolved=$(awk -F '\t' 'NR > 1 && $0 !~ /^#/ {
		    if ($3 == "pending") n++
		    if ($5 == "pending") n++
		} END { print n + 0 }' \
		    "$vmm/vmx-nested-default-policy-live-qualification.tsv")
	else
		nested_unresolved=0
		nested_default_unresolved=0
	fi
	nonvirtio_unresolved=$(awk -F '\t' 'NR > 1 && $0 !~ /^#/ {
	    if ($4 == "pending" || $4 == "environment-dependent") n++
	    if ($6 == "pending" || $6 == "environment-dependent") n++
	    if ($8 == "pending" || $8 == "environment-dependent") n++
	} END { print n + 0 }' "$nonvirtio")
	if [ "$virtio_unresolved" -ne 0 ] || [ "$nested_unresolved" -ne 0 ] ||
	    [ "$nested_default_unresolved" -ne 0 ] ||
	    [ "$nonvirtio_unresolved" -ne 0 ]; then
		status
		fail "release coverage unresolved: VirtIO=$virtio_unresolved nested=$nested_unresolved nested-default=$nested_default_unresolved non-VirtIO=$nonvirtio_unresolved"
	fi
	echo "PASS WASPNest release coverage gate"
}

qualification()
{
	mode=$1
	require_payload
	if [ -n "${PROFILE:-}" ]; then
		profile=$PROFILE
	elif sysctl -n hw.vmm.vmx.initialized 2>/dev/null | grep -qx 1; then
		profile=full-qualification
	else
		profile=qualification
	fi
	if [ "$mode" = run ]; then
		require_root run
		require_privileged_payload
		PROFILE=$profile
		export PROFILE
		# Reject an incomplete or malformed campaign configuration before the
		# expensive host/audit preflights and before any host mutation.
		PLAN_ONLY=yes "$e2e/run-waspnest-qualification.sh" >/dev/null
		post_reboot
		audit
		run_campaign
		release_ready
		return
	fi
	PROFILE=$profile
	export PROFILE
	PLAN_ONLY=yes "$e2e/run-waspnest-qualification.sh"
}

usage()
{
	echo "usage: waspnest-test {list|status|post-reboot|audit|host|plan|release-ready|run}" >&2
	exit 2
}

[ "$#" -eq 1 ] || usage
case "$1" in
list) list_gates ;;
status) status ;;
post-reboot) post_reboot ;;
audit) audit ;;
host) host_tests ;;
plan) qualification plan ;;
release-ready) release_ready ;;
run) qualification run ;;
*) usage ;;
esac
