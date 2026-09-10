#
# SPDX-License-Identifier: BSD-2-Clause
#

helper="@SRCTOP@/usr.sbin/switchboardctl/switchboard-pkg-reclaim.sh"

atf_test_case arguments
arguments_body()
{
	atf_check -s exit:64 -o empty -e match:'usage:' /bin/sh "$helper"
	for label in '/absolute' '../escape' 'bad label'; do
		atf_check -s exit:64 -o empty -e match:'invalid label' \
		    /bin/sh "$helper" "$label"
	done
	long=$(jot -b x -s '' 64)
	atf_check -s exit:64 -o empty -e match:'label too long' \
	    /bin/sh "$helper" "$long"
}

atf_test_case offline_roots_never_contact_host
offline_roots_never_contact_host_body()
{
	trace="$(pwd)/trace"
	fake="@SRCTOP@/usr.sbin/switchboardctl/tests/pkg_reclaim_fake.sh"
	for root in /tmp/offline /altroot; do
		atf_check -s exit:0 -o empty -e empty env \
		    PKG_ROOTDIR="$root" SWITCHBOARD_PKG_RECLAIM_TESTING=yes \
		    SWITCHBOARD_PKG_RECLAIM_CTL="$fake" \
		    SWITCHBOARD_PKG_RECLAIM_TRACE="$trace" \
		    /bin/sh "$helper" system.Test/unit
	done
	atf_check -s exit:0 test ! -e "$trace"
}

atf_test_case upgrades_preserve_state
upgrades_preserve_state_body()
{
	trace="$(pwd)/trace"
	fake="@SRCTOP@/usr.sbin/switchboardctl/tests/pkg_reclaim_fake.sh"
	atf_check -s exit:0 -o empty -e empty env PKG_UPGRADE=1 \
	    SWITCHBOARD_PKG_RECLAIM_TESTING=yes \
	    SWITCHBOARD_PKG_RECLAIM_CTL="$fake" \
	    SWITCHBOARD_PKG_RECLAIM_TRACE="$trace" \
	    /bin/sh "$helper" system.Test/unit
	atf_check -s exit:0 test ! -e "$trace"
}

atf_test_case all_labels_are_retried
all_labels_are_retried_body()
{
	trace="$(pwd)/trace"
	fake="@SRCTOP@/usr.sbin/switchboardctl/tests/pkg_reclaim_fake.sh"
	atf_check -s exit:1 -o empty -e match:'failed after 3 attempts' env \
	    SWITCHBOARD_PKG_RECLAIM_TESTING=yes \
	    SWITCHBOARD_PKG_RECLAIM_CTL="$fake" \
	    SWITCHBOARD_PKG_RECLAIM_TRACE="$trace" \
	    SWITCHBOARD_PKG_RECLAIM_FAIL=yes \
	    /bin/sh "$helper" system.One/a system.Two/b
	atf_check -s exit:0 -o inline:'6\n' grep -c '^reclaim ' "$trace"
	atf_check -s exit:0 -o inline:'3\n' \
	    grep -c '^reclaim system.One/a$' "$trace"
	atf_check -s exit:0 -o inline:'3\n' \
	    grep -c '^reclaim system.Two/b$' "$trace"
}

atf_test_case success_covers_every_label
success_covers_every_label_body()
{
	trace="$(pwd)/trace"
	fake="@SRCTOP@/usr.sbin/switchboardctl/tests/pkg_reclaim_fake.sh"
	atf_check -s exit:0 -o empty -e empty env \
	    SWITCHBOARD_PKG_RECLAIM_TESTING=yes \
	    SWITCHBOARD_PKG_RECLAIM_CTL="$fake" \
	    SWITCHBOARD_PKG_RECLAIM_TRACE="$trace" \
	    /bin/sh "$helper" system.One/a system.Two/b
	atf_check -s exit:0 -o inline:'reclaim system.One/a\nreclaim system.Two/b\n' \
	    cat "$trace"
}

atf_test_case base_package_hooks_cover_shipped_bundles
base_package_hooks_cover_shipped_bundles_body()
{
	root="@SRCTOP@"
	while read -r manifest label; do
		atf_check -s exit:0 -o match:"$label" \
		    grep -F "$label" "$root/$manifest"
	done <<EOF
packages/auditbrokerd/auditbrokerd.ucl system.Audit/auditbrokerd
packages/authagentd/authagentd-base.ucl system.AuthAgent/authagentd
packages/bluetooth/bluetooth-base.ucl org.5bsd.Blued/blued
packages/bsdnotify/bsdnotify.ucl system.Notify/bsdnotify
packages/localcrypto/localcrypto.ucl system.Crypto/localcrypto
packages/localdevice/localdevice.ucl system.Device/localdevice
packages/localnetwork/localnetwork.ucl system.Network/localnetwork
packages/logd/logd.ucl system.Log/logd
packages/traced/traced.ucl system.Trace/traced
packages/runtime/runtime.ucl system.Filesystem/tzfsd
packages/runtime/runtime.ucl system.Namespace/warden
packages/runtime/runtime.ucl system.Sysctl/localsysctl
packages/runtime/runtime.ucl system.SystemExtension/sysextd
packages/runtime/runtime.ucl system.Waspnest/waspnest
EOF
}

atf_init_test_cases()
{
	atf_add_test_case arguments
	atf_add_test_case offline_roots_never_contact_host
	atf_add_test_case upgrades_preserve_state
	atf_add_test_case all_labels_are_retried
	atf_add_test_case success_covers_every_label
	atf_add_test_case base_package_hooks_cover_shipped_bundles
}
