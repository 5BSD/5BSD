#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# Tests for authorityd's PID 1 lifecycle control operations
# (CTL_OP_REBOOT/HALT/POWEROFF/POWERCYCLE/SINGLE/REROOT/RESCAN/
# CATATONIA), the authenticated socket replacement for init(8)'s signal
# ABI.  See docs/authority-control-abi-design.md.
#
# These run against the live control socket and exercise only the paths
# that CANNOT reboot the machine:
#
#   - a daemon-mode authorityd (getpid() != 1) rejects every lifecycle op
#     with EPERM — the request never reaches the accept path;
#   - a lifecycle op carrying a payload is rejected with EINVAL before
#     cmd_lifecycle() runs, so it is safe even against PID 1;
#   - reserved opcodes stay unimplemented (ENOTSUP).
#
# The accept path (PID 1 actually rebooting) is validated separately by
# the VM integration test, since by definition it reboots the machine.
#
# Reply wire format (struct ctl_reply): the first 4 bytes are the status
# as a little-endian uint32.  EPERM=1 (01), EINVAL=22 (16), ENOTSUP=45
# (2d).

SOCK=/var/run/authorityd.sock

# Skip when the live daemon is PID 1 (authority-init): sending an accepted
# lifecycle op there would reboot the test machine.
require_daemon_not_pid1()
{
	if [ ! -S "$SOCK" ]; then
		atf_skip "authorityd control socket not present"
	fi
	if [ "$(ps -o comm= -p 1 2>/dev/null)" = "authority-init" ]; then
		atf_skip "authorityd is PID 1; lifecycle ops would reboot the host"
	fi
}

# Emit one raw byte with decimal value $1 (0-255).  Uses octal escapes:
# the FreeBSD printf(1)/sh builtin supports \NNN but NOT \xHH, so hex
# escapes would silently emit literal text and corrupt the request.
emit_byte()
{
	printf "\\$(printf '%03o' "$1")"
}

# Emit a little-endian uint32 of decimal value $1.
emit_u32()
{
	emit_byte $(( $1 & 255 ))
	emit_byte $(( ($1 >> 8) & 255 ))
	emit_byte $(( ($1 >> 16) & 255 ))
	emit_byte $(( ($1 >> 24) & 255 ))
}

# Send one control request (version=1) and print the reply's status byte
# as two hex digits (the low byte of the little-endian uint32 status;
# every status we assert on fits in one byte).  $1 = opcode (decimal);
# $2 = datalen (decimal, default 0).  When datalen != 0, that many zero
# payload bytes follow so the daemon does not block waiting for a body it
# was told to expect.  Extracting the first od field avoids depending on
# od's leading/inter-byte spacing.
send_op()
{
	local op="$1" dlen="${2:-0}" i
	{
		emit_u32 1		# version = 1
		emit_u32 "$op"		# op
		emit_u32 0		# flags
		emit_u32 "$dlen"	# datalen
		i=0
		while [ "$i" -lt "$dlen" ]; do
			emit_byte 0
			i=$((i + 1))
		done
	} | nc -U "$SOCK" | od -A n -t x1 | head -1 | awk '{print $1}'
}

# Assert that lifecycle opcode $1 (decimal) is denied with EPERM against
# a non-PID-1 daemon.  EPERM (01) rather than ENOTSUP (2d) proves the
# opcode reaches cmd_lifecycle() and its not-PID-1 guard fires.
assert_denied_off_pid1()
{
	local status
	require_daemon_not_pid1
	status=$(send_op "$1" 0)
	case "$status" in
	01)
		;;
	2d)
		atf_fail "op $1 returned ENOTSUP; opcode not dispatched"
		;;
	*)
		atf_fail "op $1: expected EPERM (01), got status $status"
		;;
	esac
}

atf_test_case lifecycle_reboot_denied_off_pid1
lifecycle_reboot_denied_off_pid1_head()
{
	atf_set "descr" "CTL_OP_REBOOT is denied (EPERM) off PID 1"
	atf_set "require.user" "root"
}
lifecycle_reboot_denied_off_pid1_body() { assert_denied_off_pid1 4; }

atf_test_case lifecycle_halt_denied_off_pid1
lifecycle_halt_denied_off_pid1_head()
{
	atf_set "descr" "CTL_OP_HALT is denied (EPERM) off PID 1"
	atf_set "require.user" "root"
}
lifecycle_halt_denied_off_pid1_body() { assert_denied_off_pid1 5; }

atf_test_case lifecycle_poweroff_denied_off_pid1
lifecycle_poweroff_denied_off_pid1_head()
{
	atf_set "descr" "CTL_OP_POWEROFF is denied (EPERM) off PID 1"
	atf_set "require.user" "root"
}
lifecycle_poweroff_denied_off_pid1_body() { assert_denied_off_pid1 6; }

atf_test_case lifecycle_powercycle_denied_off_pid1
lifecycle_powercycle_denied_off_pid1_head()
{
	atf_set "descr" "CTL_OP_POWERCYCLE is denied (EPERM) off PID 1"
	atf_set "require.user" "root"
}
lifecycle_powercycle_denied_off_pid1_body() { assert_denied_off_pid1 10; }

atf_test_case lifecycle_single_denied_off_pid1
lifecycle_single_denied_off_pid1_head()
{
	atf_set "descr" "CTL_OP_SINGLE is denied (EPERM) off PID 1"
	atf_set "require.user" "root"
}
lifecycle_single_denied_off_pid1_body() { assert_denied_off_pid1 11; }

atf_test_case lifecycle_reroot_denied_off_pid1
lifecycle_reroot_denied_off_pid1_head()
{
	atf_set "descr" "CTL_OP_REROOT is denied (EPERM) off PID 1"
	atf_set "require.user" "root"
}
lifecycle_reroot_denied_off_pid1_body() { assert_denied_off_pid1 12; }

atf_test_case lifecycle_rescan_denied_off_pid1
lifecycle_rescan_denied_off_pid1_head()
{
	atf_set "descr" "CTL_OP_RESCAN is denied (EPERM) off PID 1"
	atf_set "require.user" "root"
}
lifecycle_rescan_denied_off_pid1_body() { assert_denied_off_pid1 13; }

atf_test_case lifecycle_catatonia_denied_off_pid1
lifecycle_catatonia_denied_off_pid1_head()
{
	atf_set "descr" "CTL_OP_CATATONIA is denied (EPERM) off PID 1"
	atf_set "require.user" "root"
}
lifecycle_catatonia_denied_off_pid1_body() { assert_denied_off_pid1 14; }

atf_test_case lifecycle_rejects_payload
lifecycle_rejects_payload_head()
{
	atf_set "descr" "a lifecycle op carrying a payload is rejected (EINVAL)"
	atf_set "require.user" "root"
}
lifecycle_rejects_payload_body()
{
	local reply
	if [ ! -S "$SOCK" ]; then
		atf_skip "authorityd control socket not present"
	fi
	# datalen != 0 is rejected in control.c before cmd_lifecycle() runs,
	# so this is safe even against a PID 1 authority-init.  EINVAL = 22 (16).
	reply=$(send_op 4 4)
	[ "$reply" = "16" ] ||
	    atf_fail "expected EINVAL (16) for payload, got status $reply"
}

atf_test_case lifecycle_reserved_op_unsupported
lifecycle_reserved_op_unsupported_head()
{
	atf_set "descr" "reserved opcodes 7-9 stay unimplemented (ENOTSUP)"
	atf_set "require.user" "root"
}
lifecycle_reserved_op_unsupported_body()
{
	local reply
	if [ ! -S "$SOCK" ]; then
		atf_skip "authorityd control socket not present"
	fi
	# op=7 (removed 'check') must not be silently wired.  ENOTSUP = 45 (2d).
	reply=$(send_op 7 0)
	[ "$reply" = "2d" ] ||
	    atf_fail "expected ENOTSUP (2d) for reserved op 7, got status $reply"
}

atf_test_case reboot_path_healthy_on_pid1
reboot_path_healthy_on_pid1_head()
{
	atf_set "descr" "on a live plane, reboot(8)'s control socket is present" \
	    "and answers, and the signal fallback stays shielded"
	atf_set "require.user" "root"
}
reboot_path_healthy_on_pid1_body()
{
	local status

	# Only meaningful when authority-init is PID 1 (a live plane); off PID 1
	# the reboot path is validated by the *_denied_off_pid1 cases above.
	if [ "$(ps -o comm= -p 1 2>/dev/null)" != "authority-init" ]; then
		atf_skip "authority-init is not PID 1; nothing to guard here"
	fi

	# 1. reboot(8)/halt(8)/shutdown(8) connect to $SOCK and fall back to the
	#    (shielded) signal ABI only when it is absent.  The 2026-08 scare was
	#    a rename skew -- PID 1 served oracled.sock while reboot(8) looked for
	#    authorityd.sock -- so reboot fell back to the signal and died with
	#    EPERM.  Guard the exact socket path reboot(8) uses.
	if [ ! -S "$SOCK" ]; then
		atf_fail "control socket $SOCK absent; reboot(8) would fall back" \
		    "to the shielded signal and fail"
	fi

	# 2. The socket must actually answer -- a live transport, not a stale
	#    node.  CTL_OP_STATUS (op 2) is non-destructive and safe against PID 1.
	status=$(send_op 2 0)
	if [ -z "$status" ]; then
		atf_fail "control socket did not answer CTL_OP_STATUS; transport dead"
	fi

	# 3. The signal fallback MUST stay shielded, or reboot(8) could silently
	#    use it instead of the authenticated socket.  SIGHUP is used because
	#    it is non-destructive even if (wrongly) delivered -- init would only
	#    re-read /etc/ttys -- so a broken shield fails the test without
	#    rebooting or wedging the host.  Expect kill(1) to fail with EPERM.
	if kill -s HUP 1 2>/dev/null; then
		atf_fail "SIGHUP to PID 1 was not shielded; the signal ABI is open"
	fi
}

atf_init_test_cases()
{
	atf_add_test_case reboot_path_healthy_on_pid1
	atf_add_test_case lifecycle_reboot_denied_off_pid1
	atf_add_test_case lifecycle_halt_denied_off_pid1
	atf_add_test_case lifecycle_poweroff_denied_off_pid1
	atf_add_test_case lifecycle_powercycle_denied_off_pid1
	atf_add_test_case lifecycle_single_denied_off_pid1
	atf_add_test_case lifecycle_reroot_denied_off_pid1
	atf_add_test_case lifecycle_rescan_denied_off_pid1
	atf_add_test_case lifecycle_catatonia_denied_off_pid1
	atf_add_test_case lifecycle_rejects_payload
	atf_add_test_case lifecycle_reserved_op_unsupported
}
