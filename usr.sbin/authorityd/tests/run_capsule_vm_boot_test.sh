#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
#
# Exercise an installed Authority PID 1 image through bhyve.  This is deliberately
# a manual, root-only test: unlike a VM liveness check, it succeeds only after
# serviced begins its /etc/rc bootstrap and Authority's authenticated convergence
# gate permits a serial getty to present login.

set -eu

usage()
{
	cat >&2 <<-EOF
	usage: IMAGE=/path/to/image $0

	Optional environment:
	  VM_NAME       bhyve name (default: capsule-boot-test-<pid>)
	  VM_MEMORY     guest memory (default: 1024M)
	  BOOT_TIMEOUT  seconds to wait for RC bootstrap and login (default: 180)
	  BOOT_LOG      serial-console log path (default: /tmp/<VM_NAME>.log)
	  EXPECTED_BANNER literal banner fragment required before login (optional)
	  INTERACTIVE   set to yes to attach the guest serial console to this terminal
	  VM_TAP        existing host tap interface to attach as guest vtnet0
	EOF
	exit 2
}

fail()
{
	echo "capsule VM boot test: FAIL: $*" >&2
	exit 1
}

boot_completed()
{
	awk -v expected_banner="$expected_banner" '
		BEGIN { banner_seen = (expected_banner == "") }
		index($0, "startup: running /etc/rc") != 0 { rc_started = 1 }
		index($0, "authority_proto: serviced ready") != 0 ||
		    index($0, "serviced converged") != 0 { converged = 1 }
		index($0, expected_banner) != 0 { banner_seen = 1 }
		rc_started && converged && banner_seen && index($0, "login:") != 0 {
			login_ready = 1
		}
		END { exit (login_ready ? 0 : 1) }
	' "$boot_log"
}

boot_failed()
{
	grep -Eq 'bundle registry init failed|system bundle scan failed|startup: failed to launch|serviced permanently failed before convergence|serviced failed [0-9]+ times, giving up' \
	    "$boot_log"
}

optional_bluetooth_started()
{
	grep -Eq 'startup: service: org\.5bsd\.blued/blued|authority_proto: ensure kernel module vhid|Virtual HID transport ready' \
	    "$boot_log"
}

image=${IMAGE:-}
[ -n "$image" ] || usage
[ -f "$image" ] && [ ! -L "$image" ] || fail "image is missing or is a symlink: $image"

vm_name=${VM_NAME:-capsule-boot-test-$$}
case "$vm_name" in
*[!A-Za-z0-9_.-]*|'') fail "invalid VM_NAME: $vm_name" ;;
esac

vm_memory=${VM_MEMORY:-1024M}
boot_timeout=${BOOT_TIMEOUT:-180}
interactive=${INTERACTIVE:-no}
vm_tap=${VM_TAP:-}
expected_banner=${EXPECTED_BANNER:-}
case "$boot_timeout" in
''|*[!0-9]*) fail "BOOT_TIMEOUT must be a positive integer" ;;
esac
[ "$boot_timeout" -gt 0 ] || fail "BOOT_TIMEOUT must be a positive integer"
case "$interactive" in
yes|no) ;;
*) fail "INTERACTIVE must be yes or no" ;;
esac
case "$vm_tap" in
'') ;;
*[!A-Za-z0-9_.-]*) fail "invalid VM_TAP: $vm_tap" ;;
esac

boot_log=${BOOT_LOG:-/tmp/$vm_name.log}
[ ! -e "$boot_log" ] || fail "refusing to overwrite existing BOOT_LOG: $boot_log"

[ "$(id -u)" -eq 0 ] || fail "must run as root"
command -v bhyve >/dev/null 2>&1 || fail "bhyve is not installed"
command -v bhyveload >/dev/null 2>&1 || fail "bhyveload is not installed"
command -v bhyvectl >/dev/null 2>&1 || fail "bhyvectl is not installed"
kldstat -q -m vmm || fail "vmm is not loaded; load the tested vmm.ko first"

bhyve_pid=
started=false
interrupted=false

stop_bhyve()
{
	local tries

	if [ -z "$bhyve_pid" ] || ! kill -0 "$bhyve_pid" 2>/dev/null; then
		return 0
	fi
	kill -TERM "$bhyve_pid" 2>/dev/null || :
	tries=0
	while kill -0 "$bhyve_pid" 2>/dev/null && [ "$tries" -lt 10 ]; do
		sleep 1
		tries=$((tries + 1))
	done
	if kill -0 "$bhyve_pid" 2>/dev/null; then
		echo "capsule VM boot test: forcibly stopping bhyve" >&2
		kill -KILL "$bhyve_pid" 2>/dev/null || :
	fi
	wait "$bhyve_pid" 2>/dev/null || :
}

cleanup()
{
	rc=$?
	trap - EXIT HUP INT TERM
	stop_bhyve
	if [ "$started" = true ]; then
		bhyvectl --destroy --vm "$vm_name" >/dev/null 2>&1 || :
	fi
	if [ "$rc" -ne 0 ] && [ "$interactive" = no ]; then
		if [ "$interrupted" = true ]; then
			echo "capsule VM boot test: FAIL: interrupted; Ctrl-C is not boot completion" >&2
		fi
		echo "serial log retained at $boot_log" >&2
		[ ! -f "$boot_log" ] || tail -n 120 "$boot_log" >&2
	fi
}

on_interrupt()
{
	if [ "$interactive" = yes ]; then
		echo "interactive VM session ended" >&2
		exit 0
	fi
	interrupted=true
	exit 130
}

trap cleanup EXIT
trap on_interrupt HUP INT TERM

echo "Booting $image as $vm_name; serial log: $boot_log"
started=true
if ! bhyveload -m "$vm_memory" -e console=comconsole \
    -e comconsole_speed=115200 -d "$image" "$vm_name"; then
	fail "bhyveload failed"
fi

set -- -D -c 2 -m "$vm_memory" -H -w -s 0,hostbridge \
    -s 3,virtio-blk,"$image"
if [ -n "$vm_tap" ]; then
	set -- "$@" -s 4,virtio-net,"$vm_tap"
fi
set -- "$@" -s 31,lpc -l com1,stdio "$vm_name"

if [ "$interactive" = yes ]; then
	echo "Starting interactive $vm_name; use Ctrl-C to end the session"
	bhyve "$@"
	echo "interactive VM session ended"
	exit 0
fi

bhyve "$@" >"$boot_log" 2>&1 &
bhyve_pid=$!

elapsed=0
while [ "$elapsed" -lt "$boot_timeout" ]; do
	if boot_failed 2>/dev/null; then
		fail "boot log contains a serviced convergence or native-service failure"
	fi
	if optional_bluetooth_started 2>/dev/null; then
		fail "clean boot started optional Blued/vhid support"
	fi
	if boot_completed 2>/dev/null; then
		echo "capsule VM boot test: PASS: serviced RC bootstrap converged and Authority-gated serial login is ready"
		exit 0
	fi
	if ! kill -0 "$bhyve_pid" 2>/dev/null; then
		wait "$bhyve_pid" || :
		fail "bhyve exited before boot completed"
	fi
	sleep 1
	elapsed=$((elapsed + 1))
done

fail "timed out after ${boot_timeout}s waiting for serviced RC bootstrap and serial login"
