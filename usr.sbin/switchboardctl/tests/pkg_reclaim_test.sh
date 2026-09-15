
require_srctree()
{
	test -r "@SRCTOP@/usr.sbin/switchboardctl/switchboard-pkg-reclaim.sh" ||
	    atf_skip "source tree (@SRCTOP@) required for this contract check"
}

# SPDX-License-Identifier: BSD-2-Clause
helper="@SRCTOP@/usr.sbin/switchboardctl/switchboard-pkg-reclaim.sh"
fake="@SRCTOP@/usr.sbin/switchboardctl/tests/pkg_reclaim_fake.sh"
transaction=11111111111111111111111111111111

atf_test_case arguments
arguments_body()
{
	require_srctree
    atf_check -s exit:64 -o empty -e match:'usage:' /bin/sh "$helper"
    atf_check -s exit:64 -o empty -e match:'usage:' /bin/sh "$helper" invalid
    atf_check -s exit:64 -o empty -e empty /bin/sh "$helper" prepare
}

atf_test_case offline_roots_never_contact_host
offline_roots_never_contact_host_body()
{
	require_srctree
    trace="$(pwd)/trace"
    for root in /tmp/offline /altroot; do
        atf_check -s exit:0 -o empty -e empty env PKG_ROOTDIR="$root" \
            SWITCHBOARD_LIFECYCLE_OPERATION="$transaction" \
            SWITCHBOARD_PKG_RECLAIM_TESTING=yes SWITCHBOARD_PKG_RECLAIM_CTL="$fake" \
            SWITCHBOARD_PKG_RECLAIM_TRACE="$trace" \
            /bin/sh "$helper" prepare pkg:fixture system.Test/unit
    done
    atf_check -s exit:0 -o inline:'lifecycle prepare /tmp/offline 11111111111111111111111111111111 pkg:fixture system.Test/unit\nlifecycle prepare /altroot 11111111111111111111111111111111 pkg:fixture system.Test/unit\n' cat "$trace"
}

atf_test_case chroot_uses_own_root
chroot_uses_own_root_body()
{
	require_srctree
    trace="$(pwd)/trace"
    atf_check -s exit:0 -o empty -e empty env PKG_ROOTDIR=/outside PKG_CHROOTED=true \
        SWITCHBOARD_LIFECYCLE_OPERATION="$transaction" \
            SWITCHBOARD_PKG_RECLAIM_TESTING=yes SWITCHBOARD_PKG_RECLAIM_CTL="$fake" \
        SWITCHBOARD_PKG_RECLAIM_TRACE="$trace" \
        /bin/sh "$helper" retire pkg:fixture system.Test/unit
    atf_check -s exit:0 -o inline:'lifecycle retire / 11111111111111111111111111111111 pkg:fixture system.Test/unit\n' cat "$trace"
}

atf_test_case upgrades_preserve_state
upgrades_preserve_state_body()
{
	require_srctree
    trace="$(pwd)/trace"
    for operation in prepare retire; do
        atf_check -s exit:0 -o empty -e empty env PKG_UPGRADE=1 \
            SWITCHBOARD_LIFECYCLE_OPERATION="$transaction" \
            SWITCHBOARD_PKG_RECLAIM_TESTING=yes SWITCHBOARD_PKG_RECLAIM_CTL="$fake" \
            SWITCHBOARD_PKG_RECLAIM_TRACE="$trace" \
            /bin/sh "$helper" "$operation" pkg:fixture system.Test/unit
    done
    atf_check -s exit:0 test ! -e "$trace"
}

atf_test_case transaction_failure_propagates
transaction_failure_propagates_body()
{
	require_srctree
    trace="$(pwd)/trace"
    atf_check -s exit:1 -o empty -e empty env \
        SWITCHBOARD_LIFECYCLE_OPERATION="$transaction" \
            SWITCHBOARD_PKG_RECLAIM_TESTING=yes SWITCHBOARD_PKG_RECLAIM_CTL="$fake" \
        SWITCHBOARD_PKG_RECLAIM_TRACE="$trace" SWITCHBOARD_PKG_RECLAIM_FAIL=yes \
        /bin/sh "$helper" prepare pkg:fixture system.One/a system.Two/b
    atf_check -s exit:0 -o inline:'lifecycle prepare / 11111111111111111111111111111111 pkg:fixture system.One/a system.Two/b\n' cat "$trace"
}

atf_test_case success_covers_every_label
success_covers_every_label_body()
{
	require_srctree
    trace="$(pwd)/trace"
    atf_check -s exit:0 -o empty -e empty env \
        SWITCHBOARD_LIFECYCLE_OPERATION="$transaction" \
            SWITCHBOARD_PKG_RECLAIM_TESTING=yes SWITCHBOARD_PKG_RECLAIM_CTL="$fake" \
        SWITCHBOARD_PKG_RECLAIM_TRACE="$trace" \
        /bin/sh "$helper" install pkg:fixture system.One/a system.Two/b
    atf_check -s exit:0 -o inline:'lifecycle finish-install / 11111111111111111111111111111111 pkg:fixture system.One/a system.Two/b\n' cat "$trace"
}

atf_test_case base_package_hooks_cover_shipped_bundles
base_package_hooks_cover_shipped_bundles_body()
{
	require_srctree
	root="@SRCTOP@"
	while read -r manifest label; do
		# Join shell continuations before checking each transition separately.
		awk '{ line = line $0; if (sub(/\\$/, "", line)) next;
		    print line; line = "" }' "$root/$manifest" > hooks
		for operation in begin-install install prepare retire; do
			atf_check awk -v label="$label" -v operation="$operation" '
			    index($0, "switchboard-pkg-reclaim " operation " ") &&
			    index($0, label) { found = 1 }
			    END { exit !found }' hooks
		done
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
packages/runtime/runtime.ucl org.5bsd.user-session
packages/runtime/runtime.ucl system.Filesystem/tzfsd
packages/runtime/runtime.ucl system.Namespace/warden
packages/runtime/runtime.ucl system.Sysctl/localsysctl
packages/runtime/runtime.ucl system.SystemExtension/sysextd
packages/runtime/runtime.ucl system.Waspnest/waspnest
EOF
}

atf_test_case missing_transaction_is_refused
missing_transaction_is_refused_body()
{
	require_srctree
    atf_check -s exit:75 -o empty -e match:'lifecycle run' env \
        SWITCHBOARD_LIFECYCLE_OPERATION= /bin/sh "$helper" prepare pkg:fixture system.Test/unit
}

atf_test_case upgrade_stages_and_commits
upgrade_stages_and_commits_body()
{
	require_srctree
    trace="$(pwd)/trace"
    for operation in begin-install install; do
        atf_check -s exit:0 -o empty -e empty env PKG_UPGRADE=1 \
            SWITCHBOARD_LIFECYCLE_OPERATION="$transaction" \
            SWITCHBOARD_PKG_RECLAIM_TESTING=yes SWITCHBOARD_PKG_RECLAIM_CTL="$fake" \
            SWITCHBOARD_PKG_RECLAIM_TRACE="$trace" \
            /bin/sh "$helper" "$operation" pkg:fixture system.Test/unit
    done
    atf_check -s exit:0 -o inline:'lifecycle begin-adopt / 11111111111111111111111111111111 pkg:fixture system.Test/unit\nlifecycle finish-install / 11111111111111111111111111111111 pkg:fixture system.Test/unit\n' cat "$trace"
}

atf_init_test_cases()
{
    atf_add_test_case missing_transaction_is_refused
    atf_add_test_case upgrade_stages_and_commits
    atf_add_test_case arguments
    atf_add_test_case offline_roots_never_contact_host
    atf_add_test_case chroot_uses_own_root
    atf_add_test_case upgrades_preserve_state
    atf_add_test_case transaction_failure_propagates
    atf_add_test_case success_covers_every_label
    atf_add_test_case base_package_hooks_cover_shipped_bundles
}
