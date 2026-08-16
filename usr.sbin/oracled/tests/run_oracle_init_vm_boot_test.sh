#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
#
# Exercise an installed Oracle PID 1 image through bhyve.  This is deliberately
# a manual, root-only test: unlike a VM liveness check, it succeeds only after
# serviced reports that /etc/rc completed and the serial getty presents login.

set -eu

usage()
{
	cat >&2 <<-EOF
	usage: IMAGE=/path/to/image $0

	Optional environment:
	  VM_NAME       bhyve name (default: oracle-init-boot-test-<pid>)
	  VM_MEMORY     guest memory (default: 1024M)
	  BOOT_TIMEOUT  seconds to wait for RC completion and login (default: 180)
	  BOOT_LOG      serial-console log path (default: /tmp/<VM_NAME>.log)
	EOF
	exit 2
}

fail()
{
	echo "oracle-init VM boot test: FAIL: $*" >&2
	exit 1
}

boot_completed()
{
	awk '
		index($0, "startup: /etc/rc completed") != 0 { rc_done = 1 }
		rc_done && index($0, "login:") != 0 { login_ready = 1 }
		END { exit (login_ready ? 0 : 1) }
	' "$boot_log"
}

image=${IMAGE:-}
[ -n "$image" ] || usage
[ -f "$image" ] && [ ! -L "$image" ] || fail "image is missing or is a symlink: $image"

vm_name=${VM_NAME:-oracle-init-boot-test-$$}
case "$vm_name" in
*[!A-Za-z0-9_.-]*|'') fail "invalid VM_NAME: $vm_name" ;;
esac

vm_memory=${VM_MEMORY:-1024M}
boot_timeout=${BOOT_TIMEOUT:-180}
case "$boot_timeout" in
''|*[!0-9]*) fail "BOOT_TIMEOUT must be a positive integer" ;;
esac
[ "$boot_timeout" -gt 0 ] || fail "BOOT_TIMEOUT must be a positive integer"

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
		echo "oracle-init VM boot test: forcibly stopping bhyve" >&2
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
	if [ "$rc" -ne 0 ]; then
		if [ "$interrupted" = true ]; then
			echo "oracle-init VM boot test: FAIL: interrupted; Ctrl-C is not boot completion" >&2
		fi
		echo "serial log retained at $boot_log" >&2
		[ ! -f "$boot_log" ] || tail -n 120 "$boot_log" >&2
	fi
}

on_interrupt()
{
	interrupted=true
	exit 130
}

trap cleanup EXIT
trap on_interrupt HUP INT TERM

echo "Booting $image as $vm_name; serial log: $boot_log"
started=true
if ! bhyveload -c /dev/null -m "$vm_memory" -e console=comconsole \
    -e comconsole_speed=115200 -d "$image" "$vm_name"; then
	fail "bhyveload failed"
fi

bhyve -D -c 2 -m "$vm_memory" -H -w -s 0,hostbridge \
    -s 3,virtio-blk,"$image" -s 31,lpc -l com1,stdio "$vm_name" \
    >"$boot_log" 2>&1 &
bhyve_pid=$!

elapsed=0
while [ "$elapsed" -lt "$boot_timeout" ]; do
	if boot_completed 2>/dev/null; then
		echo "oracle-init VM boot test: PASS: serviced completed /etc/rc and serial login is ready"
		exit 0
	fi
	if ! kill -0 "$bhyve_pid" 2>/dev/null; then
		wait "$bhyve_pid" || :
		fail "bhyve exited before boot completed"
	fi
	sleep 1
	elapsed=$((elapsed + 1))
done

fail "timed out after ${boot_timeout}s waiting for serviced RC completion and serial login"
