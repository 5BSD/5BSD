#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# Per-component reachability integration tests.
#
# For each system capability service, confirm that a program run in a login
# session can reach it over the ambient lookup channel (SERVICE_LOOKUP_FD) --
# i.e. the service is registered and can be looked up + connected, INCLUDING
# the on-demand activation a lookup must trigger.  This is the exact path a
# shell-run CLI (networkcmpctl, notifyctl, ...) takes.  It regression-guards
# two coupled fixes: the libservice client-connect path, and serviced treating
# the ambient lookup channel as a first-class on-demand requester.
#
# These pass only on a live plane (a login session that inherited an ambient
# channel).  Off the plane -- on the build host, or any session without the
# channel -- service_probe reports "no ambient channel" and the case skips.
#

# Locate the co-built probe helper: the objdir when run from the tree, or the
# same directory as this script when installed under /usr/tests.
probe_bin()
{
	if [ -n "${SERVICE_PROBE}" ] && [ -x "${SERVICE_PROBE}" ]; then
		printf '%s\n' "${SERVICE_PROBE}"
		return 0
	fi
	for p in \
	    "$(dirname "$0")/service_probe" \
	    "./service_probe"; do
		if [ -x "$p" ]; then
			printf '%s\n' "$p"
			return 0
		fi
	done
	return 1
}

# Probe one service name.  atf_skip when there is no ambient channel here (not
# a plane session); atf_pass on OK; atf_fail with the probe line otherwise.
check_reachable()
{
	local name="$1" bin out rc
	bin=$(probe_bin) || atf_skip "service_probe helper not found"
	out=$("$bin" "$name" 2>&1)
	rc=$?
	case "$rc" in
	0)	;;					# OK: reachable
	2)	atf_skip "no ambient lookup channel here: $out" ;;
	*)	atf_fail "service '$name' not reachable via ambient channel: $out" ;;
	esac
}

atf_test_case network_reachable
network_reachable_head()
{
	atf_set "descr" "system.Network is reachable + activatable via the ambient channel"
	atf_set "require.user" "root"
}
network_reachable_body() { check_reachable "system.Network"; }

atf_test_case notify_reachable
notify_reachable_head()
{
	atf_set "descr" "system.Notify is reachable + activatable via the ambient channel"
	atf_set "require.user" "root"
}
notify_reachable_body() { check_reachable "system.Notify"; }

atf_test_case audit_reachable
audit_reachable_head()
{
	atf_set "descr" "system.Audit is reachable + activatable via the ambient channel"
	atf_set "require.user" "root"
}
audit_reachable_body() { check_reachable "system.Audit"; }

atf_test_case crypto_reachable
crypto_reachable_head()
{
	atf_set "descr" "system.Crypto is reachable + activatable via the ambient channel"
	atf_set "require.user" "root"
}
crypto_reachable_body() { check_reachable "system.Crypto"; }

atf_test_case trace_reachable
trace_reachable_head()
{
	atf_set "descr" "system.Trace is reachable + activatable via the ambient channel"
	atf_set "require.user" "root"
}
trace_reachable_body() { check_reachable "system.Trace"; }

atf_test_case log_reachable
log_reachable_head()
{
	atf_set "descr" "system.Log is reachable + activatable via the ambient channel"
	atf_set "require.user" "root"
}
log_reachable_body()
{
	# logd's storage backend is ZFS: on a UFS-only image it cannot launch,
	# which is a storage-provisioning limit, not a reachability defect.
	if ! zpool list zroot >/dev/null 2>&1; then
		atf_skip "logd requires a zroot pool; none present"
	fi
	check_reachable "system.Log"
}

atf_init_test_cases()
{
	atf_add_test_case network_reachable
	atf_add_test_case notify_reachable
	atf_add_test_case audit_reachable
	atf_add_test_case crypto_reachable
	atf_add_test_case trace_reachable
	atf_add_test_case log_reachable
}
