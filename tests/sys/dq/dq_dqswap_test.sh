#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
#
# dqswap (share/examples/dq), installed beside this test, shows the
# restricted controller of dq(4): it opens the queue and attaches the
# command as root, then it and the command give up root (-u, default
# nobody), and only then does it open a substitute.  What it hands over
# is what that user can open, with that user's credential.
#
# Paths are relative to the work directory, which the user may search.
#

# Never skips: a missing device, plane or program is a failure.
require_dq()
{
	[ -c /dev/dq ] || atf_fail "/dev/dq is absent"
	[ "$(ps -o comm= -p 1)" = capsule ] ||
	    atf_fail "the capability plane is off: PID 1 is $(ps -o comm= -p 1)"
	[ -x "$(atf_get_srcdir)/dqswap" ] || atf_fail "dqswap is not installed"
	chmod 755 . || atf_fail "chmod of the work directory"
}

atf_test_case drops
drops_head()
{
	atf_set "descr" "dqswap gives up root after the attach; the command " \
	    "runs as nobody and receives the substitute"
	atf_set "require.user" "root"
}
drops_body()
{
	require_dq
	echo ORIGINAL > orig
	echo SUBSTITUTE > subst
	chmod 644 orig subst
	atf_check -s exit:0 -o inline:"65534\nSUBSTITUTE\n" -e empty \
	    "$(atf_get_srcdir)/dqswap" -l log -s orig=subst \
	    /bin/sh -c 'id -u; cat orig'
	atf_check -s exit:0 -o ignore grep -q 'now uid 65534 gid 65534' log
	atf_check -s exit:0 -o ignore grep -q 'RESOLVE open "orig" .* -> SWAP' log
}

atf_test_case cannot_reach
cannot_reach_head()
{
	atf_set "descr" "a substitute the user cannot open is not handed " \
	    "over: dqswap answers with its own open's errno"
	atf_set "require.user" "root"
}
cannot_reach_body()
{
	require_dq
	echo ORIGINAL > orig
	echo SUBSTITUTE > subst
	chmod 644 orig
	# root's, and only root's.
	chmod 600 subst
	atf_check -s not-exit:0 -o empty -e match:"Permission denied" \
	    "$(atf_get_srcdir)/dqswap" -l log -s orig=subst /bin/cat orig
	atf_check -s exit:0 -o ignore grep -q -- '-> errno 13 (open subst)' log
	atf_check -s exit:1 -o empty grep -- '-> SWAP' log
}

atf_test_case setid_cleared
setid_cleared_head()
{
	atf_set "descr" "a write through a file the unprivileged supervisor " \
	    "opened clears the set-user-ID bit (dq(4): the file's credential)"
	atf_set "require.user" "root"
}
setid_cleared_body()
{
	require_dq
	echo ORIGINAL > orig
	printf 'x\n' > subst
	chown 65534:65534 subst
	chmod 4755 subst
	atf_check -s exit:0 -o inline:"-rwsr-xr-x\n" \
	    sh -c 'ls -l subst | cut -c1-10'
	atf_check -s exit:0 -o empty -e empty \
	    "$(atf_get_srcdir)/dqswap" -l log -s orig=subst \
	    /bin/sh -c 'echo y >> orig'
	atf_check -s exit:0 -o ignore grep -q 'RESOLVE open "orig" .* -> SWAP' log
	atf_check -s exit:0 -o inline:"x\ny\n" cat subst
	atf_check -s exit:0 -o inline:"-rwxr-xr-x\n" \
	    sh -c 'ls -l subst | cut -c1-10'
	atf_check -s exit:0 -o inline:"ORIGINAL\n" cat orig
}

atf_test_case refuses_root
refuses_root_head()
{
	atf_set "descr" "dqswap -u naming root is an error"
	atf_set "require.user" "root"
}
refuses_root_body()
{
	require_dq
	atf_check -s exit:2 -o empty -e match:"must not be root" \
	    "$(atf_get_srcdir)/dqswap" -u root -s /a=/b /usr/bin/true
	atf_check -s exit:2 -o empty -e match:"must not be root" \
	    "$(atf_get_srcdir)/dqswap" -u 0 -s /a=/b /usr/bin/true
	atf_check -s exit:2 -o empty -e match:"no such user" \
	    "$(atf_get_srcdir)/dqswap" -u dq-no-such-user -s /a=/b \
	    /usr/bin/true
}

atf_init_test_cases()
{
	atf_add_test_case drops
	atf_add_test_case cannot_reach
	atf_add_test_case setid_cleared
	atf_add_test_case refuses_root
}
