#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# Per-component reachability integration tests.
#
# Confirm what a program run in a login session can reach over the ambient
# lookup channel (SERVICE_LOOKUP_FD), including the on-demand activation a
# lookup must trigger.  Reach is decided by the caller's software identity:
# user-visible services (Notify, Log, Time, Power, Sysctl) are open to any
# session, each provider's own policy still bounding what a caller may do;
# SYSTEM-only and
# attribute-gated names are refused to unapproved programs; approved software
# reaches its gated endpoint from the same session (networkcmpctl holds
# system.network.admin and opens system.Network.Admin).  It also
# regression-guards the libservice client-connect path and switchboard
# treating the ambient lookup channel as a first-class on-demand requester.
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

# Access is decided by the caller's software identity, not by the login
# session: the probe helper is not approved software, so SYSTEM-only and
# attribute-gated names must be refused to it exactly like unregistered ones.
check_refused()
{
	local name="$1" bin out rc
	bin=$(probe_bin) || atf_skip "service_probe helper not found"
	out=$("$bin" "$name" 2>&1)
	rc=$?
	case "$rc" in
	2)	atf_skip "no ambient lookup channel here: $out" ;;
	1)	case "$out" in
		*"errno=2 "*) ;;			# ENOENT: refused as unregistered
		*)	atf_fail "'$name' refused with the wrong error: $out" ;;
		esac ;;
	*)	atf_fail "unapproved program reached '$name': $out" ;;
	esac
}

atf_test_case unapproved_refused
unapproved_refused_head()
{
	atf_set "descr" "An unapproved program cannot reach SYSTEM-only or gated names"
	atf_set "require.user" "root"
}
unapproved_refused_body()
{
	local name
	for name in system.Network system.Network.Admin system.Audit \
	    system.Crypto system.Trace; do
		check_refused "$name"
	done
}

atf_test_case networkcmpctl_approved
networkcmpctl_approved_head()
{
	atf_set "descr" "networkcmpctl reaches the broker by its own software identity"
	atf_set "require.user" "root"
	atf_set "require.progs" "networkcmpctl"
}
networkcmpctl_approved_body()
{
	local bin out

	# Same session that check_refused uses: skip off the plane.
	bin=$(probe_bin) || atf_skip "service_probe helper not found"
	out=$("$bin" system.Notify 2>&1)
	[ $? -eq 2 ] && atf_skip "no ambient lookup channel here: $out"
	atf_check -s exit:0 -o match:"^features=0x" networkcmpctl info
}

atf_test_case notify_reachable
notify_reachable_head()
{
	atf_set "descr" "system.Notify is reachable + activatable via the ambient channel"
	atf_set "require.user" "root"
}
notify_reachable_body() { check_reachable "system.Notify"; }

atf_test_case log_reachable
log_reachable_head()
{
	atf_set "descr" "system.Log is reachable + activatable via the ambient channel"
	atf_set "require.user" "root"
}
log_reachable_body()
{
	# bsdlog's storage backend is ZFS: on a UFS-only image it cannot launch,
	# which is a storage-provisioning limit, not a reachability defect.
	if ! zpool list zroot >/dev/null 2>&1; then
		atf_skip "bsdlog requires a zroot pool; none present"
	fi
	check_reachable "system.Log"
}

# Operator services: reachable from a login session; their policy files, not
# lookup visibility, decide what a caller may change.
atf_test_case time_reachable
time_reachable_head()
{
	atf_set "descr" "system.Time is reachable via the ambient channel"
	atf_set "require.user" "root"
}
time_reachable_body() { check_reachable "system.Time"; }

atf_test_case power_reachable
power_reachable_head()
{
	atf_set "descr" "system.Power is reachable via the ambient channel"
	atf_set "require.user" "root"
}
power_reachable_body() { check_reachable "system.Power"; }

atf_test_case sysctl_reachable
sysctl_reachable_head()
{
	atf_set "descr" "system.Sysctl is reachable via the ambient channel"
	atf_set "require.user" "root"
}
sysctl_reachable_body() { check_reachable "system.Sysctl"; }

atf_init_test_cases()
{
	atf_add_test_case unapproved_refused
	atf_add_test_case networkcmpctl_approved
	atf_add_test_case notify_reachable
	atf_add_test_case log_reachable
	atf_add_test_case time_reachable
	atf_add_test_case power_reachable
	atf_add_test_case sysctl_reachable
}
