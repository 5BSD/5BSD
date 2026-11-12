#
# SPDX-License-Identifier: BSD-2-Clause
#
# The test-access setting of dq(4) and its separation from a published
# kernel (design D346, D352).
#
# The oracle is the kernel's own configuration name, kern.ident: the
# test configuration is GENERIC-DQTEST; every other kernel is treated as
# a production kernel.  No case skips: a kernel this file has no
# expectation for is a failure.
#
# Production kernel, pinned before the test option existed and required
# to hold afterwards:
#   - debug.dq.unverified_open and debug.dq.test_opens do not exist,
#     whatever the loader environment says;
#   - the booted kernel file carries neither test signature;
#   - root opens /dev/dq, an unprivileged user does not.
#

TEST_IDENT=GENERIC-DQTEST
MARKER='@(#)5BSD DQ_TEST_OPEN test kernel: not for publication'
SYMBOLS='dq_testopen_'

kernel_kind()
{
	ident=$(sysctl -n kern.ident) || atf_fail 'kern.ident'
	if [ "$ident" = "$TEST_IDENT" ]; then
		atf_fail "kernel $ident: no expectations before the test option exists"
	fi
	echo "kernel ident: $ident (production expectations)"
	echo "loader debug.dq.unverified_open: $(kenv -q debug.dq.unverified_open || echo unset)"
}

atf_test_case sysctls
sysctls_head()
{
	atf_set descr 'The test sysctls exist only on the test kernel'
	atf_set require.user root
}
sysctls_body()
{
	kernel_kind
	for oid in debug.dq.unverified_open debug.dq.test_opens; do
		atf_check -s exit:1 -o empty -e match:"unknown oid '$oid'" \
		    sysctl -n $oid
	done
	# The node itself is the production fault-injection node.
	atf_check -s exit:0 -o match:'^[0-9]+$' -e empty \
	    sysctl -n debug.dq.fail_vm_create
}

atf_test_case kernel_file
kernel_file_head()
{
	atf_set descr 'The booted kernel file carries the signatures only on the test kernel'
	atf_set require.user root
}
kernel_file_body()
{
	kernel_kind
	bootfile=$(sysctl -n kern.bootfile)
	[ -s "$bootfile" ] || atf_fail "kern.bootfile $bootfile is not a file"
	atf_check -s exit:1 -o empty -e empty grep -a -q -F -e "$MARKER" "$bootfile"
	atf_check -s exit:1 -o empty -e empty grep -a -q -F -e "$SYMBOLS" "$bootfile"
}

atf_test_case open_root
open_root_head()
{
	atf_set descr 'Root opens the queue device as before'
	atf_set require.user root
}
open_root_body()
{
	kernel_kind
	atf_check -s exit:0 -o empty -e empty sh -c 'exec 3<>/dev/dq'
}

atf_test_case open_unprivileged
open_unprivileged_head()
{
	atf_set descr 'An unprivileged user cannot open the queue device, whatever the setting'
	atf_set require.user root
}
open_unprivileged_body()
{
	kernel_kind
	# su -m runs the caller's shell, whatever it is: name sh.
	atf_check -s not-exit:0 -o empty -e match:'Permission denied' \
	    su -m nobody -c "/bin/sh -c 'exec 3<>/dev/dq'"
}

atf_init_test_cases()
{
	atf_add_test_case sysctls
	atf_add_test_case kernel_file
	atf_add_test_case open_root
	atf_add_test_case open_unprivileged
}
