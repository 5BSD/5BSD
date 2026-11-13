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
# Test kernel (options DQ_TEST_OPEN):
#   - both sysctls exist and cannot be written; unverified_open is 1 only
#     when the loader set it to exactly 1;
#   - the booted kernel file carries both signatures, the ones
#     release/scripts/check-kernel-no-dq-test.sh refuses;
#   - who may open /dev/dq is unchanged: root does, an unprivileged user
#     does not, with the tunable set or clear;
#   - test_opens counts an open that passed every check of dq_open(),
#     and only when the tunable is 1; a refused open is never counted.
#

TEST_IDENT=GENERIC-DQTEST
MARKER='@(#)5BSD DQ_TEST_OPEN test kernel: not for publication'
SYMBOLS='dq_testopen_'

# Sets kind (production or test) and, on a test kernel, expect (the value
# debug.dq.unverified_open must have, from the loader environment).
kernel_kind()
{
	ident=$(sysctl -n kern.ident) || atf_fail 'kern.ident'
	loader=$(kenv -q debug.dq.unverified_open || echo unset)
	if [ "$ident" = "$TEST_IDENT" ]; then
		kind=test
		if [ "$loader" = 1 ]; then
			expect=1
		else
			expect=0
		fi
	else
		kind=production
	fi
	echo "kernel ident: $ident ($kind expectations)"
	echo "loader debug.dq.unverified_open: $loader"
}

test_opens()
{
	sysctl -n debug.dq.test_opens || atf_fail 'debug.dq.test_opens'
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
	# The node itself is the production fault-injection node.
	atf_check -s exit:0 -o match:'^[0-9]+$' -e empty \
	    sysctl -n debug.dq.fail_vm_create
	if [ $kind = production ]; then
		for oid in debug.dq.unverified_open debug.dq.test_opens; do
			atf_check -s exit:1 -o empty \
			    -e match:"unknown oid '$oid'" sysctl -n $oid
		done
		return
	fi
	atf_check -s exit:0 -o inline:"$expect\n" -e empty \
	    sysctl -n debug.dq.unverified_open
	atf_check -s exit:0 -o match:'^[0-9]+$' -e empty \
	    sysctl -n debug.dq.test_opens
	# Neither can be written, by root, after boot.
	before=$(test_opens)
	for value in 0 1; do
		atf_check -s not-exit:0 -o ignore -e not-empty \
		    sysctl debug.dq.unverified_open=$value
	done
	atf_check -s not-exit:0 -o ignore -e not-empty \
	    sysctl debug.dq.test_opens=0
	atf_check -s exit:0 -o inline:"$expect\n" -e empty \
	    sysctl -n debug.dq.unverified_open
	atf_check_equal "$before" "$(test_opens)"
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
	if [ $kind = production ]; then
		status=1
	else
		status=0
	fi
	atf_check -s exit:$status -o empty -e empty \
	    grep -a -q -F -e "$MARKER" "$bootfile"
	atf_check -s exit:$status -o empty -e empty \
	    grep -a -q -F -e "$SYMBOLS" "$bootfile"
	# The split debug file, where one is installed: publication reads it
	# too, and a production one carries neither signature.
	debugfile=/usr/lib/debug$bootfile.debug
	if [ -e "$debugfile" ]; then
		atf_check -s exit:$status -o empty -e empty \
		    grep -a -q -F -e "$MARKER" "$debugfile"
		atf_check -s exit:$status -o empty -e empty \
		    grep -a -q -F -e "$SYMBOLS" "$debugfile"
	fi
}

atf_test_case open_root
open_root_head()
{
	atf_set descr 'Root opens the queue device as before'
	atf_set require.user root
	atf_set is.exclusive true
}
open_root_body()
{
	kernel_kind
	if [ $kind = test ]; then
		before=$(test_opens)
	fi
	atf_check -s exit:0 -o empty -e empty sh -c 'exec 3<>/dev/dq'
	if [ $kind = test ]; then
		# Counted only with the tunable set, once per open.
		atf_check_equal $((before + expect)) "$(test_opens)"
		atf_check -s exit:0 -o empty -e empty \
		    sh -c 'exec 3<>/dev/dq; exec 4<>/dev/dq'
		atf_check_equal $((before + 3 * expect)) "$(test_opens)"
	fi
}

atf_test_case open_unprivileged
open_unprivileged_head()
{
	atf_set descr 'An unprivileged user cannot open the queue device, whatever the setting'
	atf_set require.user root
	atf_set is.exclusive true
}
open_unprivileged_body()
{
	kernel_kind
	if [ $kind = test ]; then
		before=$(test_opens)
	fi
	# su -m runs the caller's shell, whatever it is: name sh.
	atf_check -s not-exit:0 -o empty -e match:'Permission denied' \
	    su -m nobody -c "/bin/sh -c 'exec 3<>/dev/dq'"
	if [ $kind = test ]; then
		# A refused open is never counted.
		atf_check_equal "$before" "$(test_opens)"
	fi
}

atf_init_test_cases()
{
	atf_add_test_case sysctls
	atf_add_test_case kernel_file
	atf_add_test_case open_root
	atf_add_test_case open_unprivileged
}
