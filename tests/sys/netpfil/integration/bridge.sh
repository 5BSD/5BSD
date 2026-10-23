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

# OpenBSD PF behind FreeBSD's if_bridge and if_enc pfil(9) hooks.  The
# bridge decides where pf sees bridged traffic (net.link.bridge.pfil_member
# and pfil_bridge); IPsec decides whether decapsulated traffic is filtered
# on enc0 only or also on the receiving interface
# (net.inet.ipsec.filtertunnel).  Rule counters (pfctl -sl) show which
# hooks pf ran on.  VLAN priority (set prio -> PCP) is covered by
# ../pf/prio.sh and ../pf/priority.sh, the basic block/pass through a bridge
# by ../pf/pass_block.sh:bridge_filter, and if_enc rdr-to by
# ../pf/if_enc.sh.

. $(atf_get_srcdir)/integration.subr

# label_pkts jail label: packets counted by the rule with that label.
label_pkts()
{
	jexec $1 pfctl -sl | awk -v l="$2" '$1 == l { print $3 }'
}

# bridge_setup: jail "left" (192.0.2.1, 2001:db8::1) and jail "right"
# (192.0.2.2, 2001:db8::2) joined by bridge ${bridge} in jail "br", whose
# members are ${l}b and ${r}a.  pf is enabled in "br".
bridge_setup()
{
	pft_init
	vnet_init_bridge
	l=$(vnet_mkepair)
	r=$(vnet_mkepair)
	vnet_mkjail left ${l}a
	vnet_mkjail right ${r}b
	vnet_mkjail br ${l}b ${r}a
	jexec left ifconfig ${l}a 192.0.2.1/24 up
	jexec left ifconfig ${l}a inet6 2001:db8::1/64 no_dad
	jexec right ifconfig ${r}b 192.0.2.2/24 up
	jexec right ifconfig ${r}b inet6 2001:db8::2/64 no_dad
	bridge=$(jexec br ifconfig bridge create)
	jexec br ifconfig ${l}b up
	jexec br ifconfig ${r}a up
	jexec br ifconfig ${bridge} addm ${l}b addm ${r}a up
	jexec br pfctl -e >/dev/null 2>&1
}

# bridge_mode member bridge: set the two pfil sysctls in "br".
bridge_mode()
{
	atf_check -s exit:0 -o ignore jexec br sysctl \
	    net.link.bridge.pfil_member=$1 net.link.bridge.pfil_bridge=$2
}

# count_hooks member bridge: load counting rules, ping three times across
# the bridge and check how many packets each hook showed pf.
count_hooks()
{
	bridge_mode $1 $2
	pft_set_rules br \
	    "pass in quick on ${l}b inet proto icmp no state label m_in" \
	    "pass out quick on ${r}a inet proto icmp no state label m_out" \
	    "pass in quick on ${bridge} inet proto icmp no state label b_in" \
	    "pass out quick on ${bridge} inet proto icmp no state label b_out" \
	    "pass no state"
	atf_check -s exit:0 -o ignore jexec left ping -c 3 -t 5 192.0.2.2

	# Requests enter ${l}b and leave ${r}a; requests and replies both
	# cross the bridge interface.
	if [ $1 -eq 1 ]; then m=3; else m=0; fi
	if [ $2 -eq 1 ]; then b=6; else b=0; fi
	atf_check_equal ${m} "$(label_pkts br m_in)"
	atf_check_equal ${m} "$(label_pkts br m_out)"
	atf_check_equal ${b} "$(label_pkts br b_in)"
	atf_check_equal ${b} "$(label_pkts br b_out)"
}

atf_test_case "defaults_unfiltered" "cleanup"
defaults_unfiltered_head()
{
	atf_set descr 'A new VNET starts with pfil_member=0 pfil_bridge=0 pfil_onlyip=1 pfil_local_phys=0; pf then never sees bridged traffic'
	atf_set require.user root
}

defaults_unfiltered_body()
{
	bridge_setup
	atf_check -s exit:0 -o inline:'0\n' \
	    jexec br sysctl -n net.link.bridge.pfil_member
	atf_check -s exit:0 -o inline:'0\n' \
	    jexec br sysctl -n net.link.bridge.pfil_bridge
	atf_check -s exit:0 -o inline:'1\n' \
	    jexec br sysctl -n net.link.bridge.pfil_onlyip
	atf_check -s exit:0 -o inline:'0\n' \
	    jexec br sysctl -n net.link.bridge.pfil_local_phys

	# Only the bridged echo traffic is counted (the bridge jail's own
	# IPv6 link-local chatter goes through the ordinary IPv6 hooks).
	pft_set_rules br \
	    "block quick inet proto icmp from 192.0.2.1 label all_block" \
	    "pass"
	atf_check -s exit:0 -o ignore jexec left ping -c 2 -t 5 192.0.2.2
	atf_check_equal 0 "$(label_pkts br all_block)"
}

defaults_unfiltered_cleanup()
{
	integ_cleanup
}

atf_test_case "hooks_member" "cleanup"
hooks_member_head()
{
	atf_set descr 'pfil_member=1: pf sees bridged packets in on the ingress member and out on the egress member, never on the bridge'
	atf_set require.user root
}

hooks_member_body()
{
	bridge_setup
	count_hooks 1 0
}

hooks_member_cleanup()
{
	integ_cleanup
}

atf_test_case "hooks_bridge" "cleanup"
hooks_bridge_head()
{
	atf_set descr 'pfil_bridge=1: pf sees bridged packets in and out on the bridge interface, never on the members'
	atf_set require.user root
}

hooks_bridge_body()
{
	bridge_setup
	count_hooks 0 1
}

hooks_bridge_cleanup()
{
	integ_cleanup
}

atf_test_case "hooks_both" "cleanup"
hooks_both_head()
{
	atf_set descr 'pfil_member=1 pfil_bridge=1: pf sees each bridged packet on the member and on the bridge'
	atf_set require.user root
}

hooks_both_body()
{
	bridge_setup
	count_hooks 1 1
}

hooks_both_cleanup()
{
	integ_cleanup
}

atf_test_case "hooks_none" "cleanup"
hooks_none_head()
{
	atf_set descr 'Turning both bridge pfil sysctls off again stops pf from seeing bridged packets'
	atf_set require.user root
}

hooks_none_body()
{
	bridge_setup
	count_hooks 1 1
	count_hooks 0 0
}

hooks_none_cleanup()
{
	integ_cleanup
}

atf_test_case "block_scoped" "cleanup"
block_scoped_head()
{
	atf_set descr 'A block rule on a member only drops in member mode, a block on the bridge only in bridge mode'
	atf_set require.user root
}

block_scoped_body()
{
	bridge_setup

	bridge_mode 1 0
	pft_set_rules br "block in quick on ${bridge} inet proto icmp" "pass"
	atf_check -s exit:0 -o ignore jexec left ping -c 1 -t 3 192.0.2.2
	pft_set_rules br "block in quick on ${l}b inet proto icmp" "pass"
	atf_check -s exit:2 -o ignore jexec left ping -c 1 -t 3 192.0.2.2

	bridge_mode 0 1
	atf_check -s exit:0 -o ignore jexec left ping -c 1 -t 3 192.0.2.2
	pft_set_rules br "block in quick on ${bridge} inet proto icmp" "pass"
	atf_check -s exit:2 -o ignore jexec left ping -c 1 -t 3 192.0.2.2
}

block_scoped_cleanup()
{
	integ_cleanup
}

atf_test_case "member_inet6" "cleanup"
member_inet6_head()
{
	atf_set descr 'Member-mode filtering of bridged IPv6: echo requests counted on both members, neighbour discovery unaffected by a block on echo requests'
	atf_set require.user root
}

member_inet6_body()
{
	bridge_setup
	bridge_mode 1 0
	pft_set_rules br \
	    "pass in quick on ${l}b inet6 proto ipv6-icmp icmp6-type echoreq no state label m6_in" \
	    "pass out quick on ${r}a inet6 proto ipv6-icmp icmp6-type echoreq no state label m6_out" \
	    "pass no state"
	atf_check -s exit:0 -o ignore jexec left ping -6 -c 3 2001:db8::2
	atf_check_equal 3 "$(label_pkts br m6_in)"
	atf_check_equal 3 "$(label_pkts br m6_out)"

	pft_set_rules br \
	    "block in quick on ${l}b inet6 proto ipv6-icmp icmp6-type echoreq label m6_block" \
	    "pass no state"
	atf_check -s exit:2 -o ignore jexec left ping -6 -c 2 2001:db8::2
	atf_check_equal 2 "$(label_pkts br m6_block)"
	# Neighbour discovery still crosses the bridge.
	atf_check -s exit:0 -o match:'2001:db8::2' jexec left ndp -an
}

member_inet6_cleanup()
{
	integ_cleanup
}

# enc_setup: a (1.0.0.11) -- agw (1.0.0.1 / 2.0.0.22) == ESP tunnel ==
# bgw (2.0.0.33 / 4.0.0.1) -- b (4.0.0.44); pf enabled on bgw, which sees
# decapsulated packets on enc0 after the outer header is stripped.
enc_setup()
{
	pft_init
	sysctl -q kern.features.ipsec >/dev/null ||
	    atf_skip "This test requires IPsec (kern.features.ipsec)"
	kldstat -q -m if_enc ||
	    atf_skip "This test requires if_enc (preload it: capability plane)"

	alan=$(vnet_mkepair)
	wan=$(vnet_mkepair)
	blan=$(vnet_mkepair)
	vnet_mkjail a ${alan}a
	vnet_mkjail agw ${alan}b ${wan}a
	vnet_mkjail bgw ${wan}b ${blan}a
	vnet_mkjail b ${blan}b

	jexec a ifconfig ${alan}a 1.0.0.11/24 up
	jexec a route add default 1.0.0.1
	jexec agw ifconfig ${alan}b 1.0.0.1/24 up
	jexec agw ifconfig ${wan}a 2.0.0.22/24 up
	jexec agw sysctl net.inet.ip.forwarding=1 >/dev/null
	jexec bgw ifconfig ${wan}b 2.0.0.33/24 up
	jexec bgw ifconfig ${blan}a 4.0.0.1/24 up
	jexec bgw sysctl net.inet.ip.forwarding=1 >/dev/null
	jexec b ifconfig ${blan}b 4.0.0.44/24 up
	jexec b route add default 4.0.0.1

	echo '
		spdadd 1.0.0.0/24 4.0.0.0/24 any -P out ipsec esp/tunnel/2.0.0.22-2.0.0.33/require;
		spdadd 4.0.0.0/24 1.0.0.0/24 any -P in  ipsec esp/tunnel/2.0.0.33-2.0.0.22/require;
		add 2.0.0.22 2.0.0.33 esp 0x203 -E aes-gcm-16 "123456789012345678901234567890123456";
		add 2.0.0.33 2.0.0.22 esp 0x302 -E aes-gcm-16 "123456789012345678901234567890123456";
	' | jexec agw setkey -c
	echo '
		spdadd 4.0.0.0/24 1.0.0.0/24 any -P out ipsec esp/tunnel/2.0.0.33-2.0.0.22/require;
		spdadd 1.0.0.0/24 4.0.0.0/24 any -P in  ipsec esp/tunnel/2.0.0.22-2.0.0.33/require;
		add 2.0.0.22 2.0.0.33 esp 0x203 -E aes-gcm-16 "123456789012345678901234567890123456";
		add 2.0.0.33 2.0.0.22 esp 0x302 -E aes-gcm-16 "123456789012345678901234567890123456";
	' | jexec bgw setkey -c

	jexec bgw ifconfig enc0 up
	jexec bgw sysctl net.enc.in.ipsec_filter_mask=2 >/dev/null
	jexec bgw pfctl -e >/dev/null 2>&1
}

atf_test_case "enc_filtertunnel" "cleanup"
enc_filtertunnel_head()
{
	atf_set descr 'Decapsulated IPsec traffic is filtered on enc0; with net.inet.ipsec.filtertunnel=1 pf also filters it on the receiving interface'
	atf_set require.user root
	atf_set require.progs setkey
}

enc_filtertunnel_body()
{
	enc_setup
	# Stateless on enc0, so the second evaluation on the wire interface
	# does not find a state and reaches the block rule.
	pft_set_rules bgw \
	    "pass in quick on enc0 inet proto icmp from 1.0.0.0/24 no state label enc_in" \
	    "block in quick on ! enc0 inet proto icmp from 1.0.0.0/24 label tun_block" \
	    "pass"

	atf_check -s exit:0 -o inline:'0\n' \
	    jexec bgw sysctl -n net.inet.ipsec.filtertunnel
	atf_check -s exit:0 -o ignore jexec a ping -c 3 -t 5 4.0.0.44
	atf_check_equal 3 "$(label_pkts bgw enc_in)"
	atf_check_equal 0 "$(label_pkts bgw tun_block)"

	jexec bgw sysctl net.inet.ipsec.filtertunnel=1 >/dev/null
	jexec bgw pfctl -z >/dev/null 2>&1
	atf_check -s exit:2 -o ignore jexec a ping -c 2 -t 3 4.0.0.44
	atf_check_equal 2 "$(label_pkts bgw enc_in)"
	atf_check_equal 2 "$(label_pkts bgw tun_block)"
}

enc_filtertunnel_cleanup()
{
	integ_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "defaults_unfiltered"
	atf_add_test_case "hooks_member"
	atf_add_test_case "hooks_bridge"
	atf_add_test_case "hooks_both"
	atf_add_test_case "hooks_none"
	atf_add_test_case "block_scoped"
	atf_add_test_case "member_inet6"
	atf_add_test_case "enc_filtertunnel"
}
