#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 The 5BSD Project
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

# Interface names FreeBSD allows and OpenBSD does not, as pf sees them
# (contrib/openbsd-pf/sys/net/pf_if.c, "5BSD: names"): two interfaces with
# one name, and interfaces named after groups.  ../pf/names.sh covers the
# FreeBSD cases that crashed; these cover what pf does afterwards.

. $(atf_get_srcdir)/integration.subr

atf_test_case "owner_leaves" "cleanup"
owner_leaves_head()
{
	atf_set descr 'When one of two same-named interfaces goes, the other keeps the name: rules, groups and (name) addresses'
	atf_set require.user root
}

owner_leaves_body()
{
	pft_init
	a=$(vnet_mkepair)
	b=$(vnet_mkepair)
	vnet_mkjail host ${a}a ${b}a
	vnet_mkjail peer ${a}b ${b}b
	jail -m name=host children.max=4 ||
	    atf_skip "nested jails are not available"
	jexec peer ifconfig ${a}b 192.0.2.2/24 up
	jexec peer ifconfig ${b}b 198.51.100.2/24 up
	jexec host ifconfig ${a}a 192.0.2.1/24 up

	# ${b}a gets the name "dup" in jail "inner", ${a}a in "host"; jail
	# removal returns ${b}a to "host", next to the other "dup".
	jexec host jail -c name=inner vnet persist
	jexec host ifconfig ${b}a vnet inner
	jexec host jexec inner ifconfig ${b}a name dup >/dev/null
	jexec host ifconfig ${a}a name dup >/dev/null
	jexec host jail -r inner
	atf_check -s exit:0 -o match:"dup" jexec host ifconfig -l

	jexec host pfctl -e >/dev/null 2>&1
	pft_set_rules host "pass" \
	    "pass out quick on epair inet proto icmp label grp" \
	    "pass out quick inet proto icmp from (dup:0) label dyn"

	# The interface that owned the name goes away.  ifconfig dup destroy
	# destroys whichever "dup" ifunit() finds first; destroy the one that
	# is not on 198.51.100.0/24 by its address.
	first=$(jexec host ifconfig dup | awk '/inet /{print $2; exit}')
	jexec host ifconfig dup destroy
	left=$(jexec host ifconfig dup | awk '/inet /{print $2; exit}')
	[ "${left}" != "${first}" ] ||
	    atf_skip "the remaining dup cannot be told apart"
	jexec host ifconfig dup 198.51.100.1/24 up

	# Group rules on the remaining interface, and its (dup:0) address.
	atf_check -s exit:0 -o ignore jexec host ping -c 2 -t 4 198.51.100.2
	atf_check -s exit:0 -o match:"^grp [0-9]+ [1-9]" jexec host pfctl -sl
	atf_check -s exit:0 -o match:"198.51.100.1" jexec host pfctl -sr -vv
}

owner_leaves_cleanup()
{
	jexec host jail -r inner 2>/dev/null
	pft_cleanup
}

atf_test_case "group_cycle" "cleanup"
group_cycle_head()
{
	atf_set descr 'Two interfaces named after each other'"'"'s groups survive address changes'
	atf_set require.user root
}

group_cycle_body()
{
	pft_init
	a=$(vnet_mkepair)
	b=$(vnet_mkepair)
	vnet_mkjail host ${a}a ${b}a
	jexec host pfctl -e >/dev/null 2>&1
	pft_set_rules host "pass" "pass out on foo from (foo) to (bar)"
	jexec host ifconfig ${a}a name foo >/dev/null
	jexec host ifconfig ${b}a name bar >/dev/null
	atf_check -s exit:0 jexec host ifconfig foo group bar
	atf_check -s exit:0 jexec host ifconfig bar group foo
	# Each address event refreshes the kif and its groups.
	atf_check -s exit:0 jexec host ifconfig foo 192.0.2.1/24 up
	atf_check -s exit:0 jexec host ifconfig bar 198.51.100.1/24 up
	atf_check -s exit:0 jexec host ifconfig foo -group bar
	atf_check -s exit:0 -o ignore jexec host pfctl -sr
}

group_cycle_cleanup()
{
	for i in foo bar; do
		ifconfig ${i} destroy 2>/dev/null
	done
	pft_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "owner_leaves"
	atf_add_test_case "group_cycle"
}
