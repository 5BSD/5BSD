#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2021 Rubicon Communications, LLC (Netgate)
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

. $(atf_get_srcdir)/utils.subr

common_dir=$(atf_get_srcdir)/../common

atf_test_case "many" "cleanup"
many_head()
{
	atf_set descr 'Test retrieving many states'
	atf_set require.user root
	# 20000 SYNs from scapy take most of 300 s on an emulated test VM.
	atf_set timeout 900
	atf_set require.progs python3 scapy
}

many_body()
{
	pft_init

	epair=$(vnet_mkepair)
	ifconfig ${epair}a 192.0.2.1/24 up

	vnet_mkjail alcatraz ${epair}b
	jexec alcatraz ifconfig ${epair}b 192.0.2.2/24 up
	jexec alcatraz pfctl -e

	pft_set_rules alcatraz "set timeout tcp.closed 60000" \
		"pass in proto icmp" \
		"pass in proto tcp"

	# Sanity check
	atf_check -s exit:0 -o ignore ping -c 1 -W 1 192.0.2.2

	# Now syn flood to create many states
	${common_dir}/pft_synflood.py \
		--sendif ${epair}a \
		--to 192.0.2.2 \
		--count 20000

	count=$(time jexec alcatraz pfctl -ss | wc -l 2>time.txt)
	echo "Found $count states in `cat time.txt`"
	if [ $count -lt 20000 ];
	then
		atf_fail "Fail to retrieve states"
	fi
}

many_cleanup()
{
	rm -f time.txt
	pft_cleanup
}

atf_test_case "rule" "cleanup"
rule_head()
{
	atf_set descr 'Test retrieving original state establishing rule'
	atf_set require.user root
}

rule_body()
{
	pft_init

	epair=$(vnet_mkepair)
	ifconfig ${epair}a 192.0.2.1/24 up

	vnet_mkjail alcatraz ${epair}b
	jexec alcatraz ifconfig ${epair}b 192.0.2.2/24 up
	jexec alcatraz pfctl -e

	pft_set_rules alcatraz \
		"pass in proto icmp label \"icmplabel\""

	# Establish state
	atf_check -o ignore ping -c 1 -W 1 192.0.2.2

	# We should see the rule now.  OpenBSD's pfctl -ss -v identifies the
	# rule that created the state by its number, not by its text.
	atf_check -o match:", rule 0$" \
	    -e ignore \
	    jexec alcatraz pfctl -ss -vv

	# The pass rule of the new ruleset is @1, so a state that followed
	# it would report rule 1.
	pft_set_rules noflush alcatraz \
	    "block in proto tcp" \
	    "pass"

	# Even after the rules changes the state keeps its original rule,
	# with the original rule's label.  5BSD: OpenBSD pf numbers a rule
	# that is no longer in the ruleset -1 (pf_rm_rule()), so pfctl
	# prints no rule number for the state.
	atf_check -o not-match:", rule [0-9]+$" \
	    -e ignore \
	    jexec alcatraz pfctl -ss -vv
	atf_check -s exit:0 -e match:"killed 1 states" \
	    jexec alcatraz pfctl -k label -k icmplabel
	atf_check -s exit:0 -o empty -e ignore \
	    jexec alcatraz pfctl -ss
}

rule_cleanup()
{
	pft_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "many"
	atf_add_test_case "rule"
}
