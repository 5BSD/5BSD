#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2018 Kristof Provost <kp@FreeBSD.org>
# Copyright (c) 2025 Kajetan Staszkiewicz <ks@FreeBSD.org>
# Copyright (c) 2021 KUROSAWA Takahiro <takahiro.kurosawa@gmail.com>
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

atf_test_case "exhaust" "cleanup"
exhaust_head()
{
	atf_set descr 'Test exhausting the NAT pool'
	atf_set require.user root
}

exhaust_body()
{
	pft_init

	epair_nat=$(vnet_mkepair)
	epair_echo=$(vnet_mkepair)

	vnet_mkjail nat ${epair_nat}b ${epair_echo}a
	vnet_mkjail echo ${epair_echo}b

	ifconfig ${epair_nat}a 192.0.2.2/24 up
	route add -net 198.51.100.0/24 192.0.2.1

	jexec nat ifconfig ${epair_nat}b 192.0.2.1/24 up
	jexec nat ifconfig ${epair_echo}a 198.51.100.1/24 up
	jexec nat sysctl net.inet.ip.forwarding=1

	jexec echo ifconfig ${epair_echo}b 198.51.100.2/24 up
	jexec echo /usr/sbin/inetd -p ${PWD}/inetd-echo.pid $(atf_get_srcdir)/echo_inetd.conf

	# Disable checksum offload on one of the interfaces to ensure pf handles that
	jexec nat ifconfig ${epair_nat}a -txcsum

	# Enable pf!
	jexec nat pfctl -e
	pft_set_rules nat \
		"pass out on ${epair_echo}a inet from 192.0.2.0/24 to any nat-to (${epair_echo}a) port 30000:30001 sticky-address"

	# Sanity check
	atf_check -s exit:0 -o ignore ping -c 3 198.51.100.2

	atf_check -s exit:0 -o match:foo* echo "foo" | nc -N 198.51.100.2 7
	atf_check -s exit:0 -o match:foo* echo "foo" | nc -N 198.51.100.2 7

	# This one will fail, but that's expected
	echo "foo" | nc -N 198.51.100.2 7 &

	sleep 1

	# If the kernel is stuck in pf_get_sport() this will not succeed either.
	timeout 2 jexec nat pfctl -sa
	if [ $? -eq 124 ]; then
		# Timed out
		atf_fail "pfctl timeout"
	fi
}

exhaust_cleanup()
{
	pft_cleanup
}

atf_test_case "nat6_nolinklocal" "cleanup"
nat6_nolinklocal_head()
{
	atf_set descr 'Ensure we do not use link-local addresses'
	atf_set require.user root
}

nat6_nolinklocal_body()
{
	pft_init

	epair_nat=$(vnet_mkepair)
	epair_echo=$(vnet_mkepair)

	vnet_mkjail nat ${epair_nat}b ${epair_echo}a
	vnet_mkjail echo ${epair_echo}b

	ifconfig ${epair_nat}a inet6 2001:db8::2/64 no_dad up
	route add -6 -net 2001:db8:1::/64 2001:db8::1

	jexec nat ifconfig ${epair_nat}b inet6 2001:db8::1/64 no_dad up
	jexec nat ifconfig ${epair_echo}a inet6 2001:db8:1::1/64 no_dad up
	jexec nat sysctl net.inet6.ip6.forwarding=1

	jexec echo ifconfig ${epair_echo}b inet6 2001:db8:1::2/64 no_dad up
	# Ensure we can't reply to link-local pings
	jexec echo pfctl -e
	pft_set_rules echo \
	    "pass" \
	    "block in inet6 proto icmp6 from fe80::/10 to any icmp6-type echoreq"

	# Keep the inbound leg stateless so it cannot create a floating state
	# that bypasses the outbound NAT rule.
	jexec nat pfctl -e
	pft_set_rules nat \
	    "pass in no state" \
	    "pass out on ${epair_echo}a inet6 from 2001:db8::/64 to any nat-to (${epair_echo}a)"

	# Sanity check
	atf_check -s exit:0 -o ignore \
	    ping -6 -c 1 2001:db8::1
	for i in `seq 0 10`
	do
		atf_check -s exit:0 -o ignore \
		    ping -6 -c 1 2001:db8:1::2
	done
}

nat6_nolinklocal_cleanup()
{
	pft_cleanup
}

empty_table_common()
{
	option=$1

	pft_init

	epair_wan=$(vnet_mkepair)
	epair_lan=$(vnet_mkepair)

	vnet_mkjail srv ${epair_wan}a
	jexec srv ifconfig ${epair_wan}a 192.0.2.2/24 up

	vnet_mkjail rtr ${epair_wan}b ${epair_lan}a
	jexec rtr ifconfig ${epair_wan}b 192.0.2.1/24 up
	jexec rtr ifconfig ${epair_lan}a 198.51.100.1/24 up
	jexec rtr sysctl net.inet.ip.forwarding=1

	ifconfig ${epair_lan}b 198.51.100.2/24 up
	route add default 198.51.100.1

	jexec rtr pfctl -e
	pft_set_rules rtr \
	    "table <empty>" \
	    "match out on ${epair_wan}b inet from 198.51.100.0/24 nat-to <empty> ${option}" \
	    "pass"

	# Sanity checks
	atf_check -s exit:0 -o ignore \
	    jexec rtr ping -c 1 192.0.2.2
	atf_check -s exit:0 -o ignore \
	    ping -c 1 198.51.100.1
	atf_check -s exit:0 -o ignore \
	    ping -c 1 192.0.2.1

	# Provoke divide by zero
	ping -c 1 192.0.2.2
	true
}

atf_test_case "empty_table_source_hash" "cleanup"
empty_table_source_hash_head()
{
	atf_set descr 'Test source-hash on an emtpy table'
	atf_set require.user root
}

empty_table_source_hash_body()
{
	empty_table_common "source-hash"
}

empty_table_source_hash_cleanup()
{
	pft_cleanup
}

atf_test_case "empty_table_random" "cleanup"
empty_table_random_head()
{
	atf_set descr 'Test random on an emtpy table'
	atf_set require.user root
}

empty_table_random_body()
{
	empty_table_common "random"
}

empty_table_random_cleanup()
{
	pft_cleanup
}

no_addrs_common()
{
	option=$1

	pft_init

	epair_wan=$(vnet_mkepair)
	epair_lan=$(vnet_mkepair)

	vnet_mkjail srv ${epair_wan}a
	jexec srv ifconfig ${epair_wan}a 192.0.2.2/24 up

	vnet_mkjail rtr ${epair_wan}b ${epair_lan}a
	jexec rtr route add -net 192.0.2.0/24 -iface ${epair_wan}b
	jexec rtr ifconfig ${epair_lan}a 198.51.100.1/24 up
	jexec rtr sysctl net.inet.ip.forwarding=1

	ifconfig ${epair_lan}b 198.51.100.2/24 up
	route add default 198.51.100.1

	jexec rtr pfctl -e
	pft_set_rules rtr \
	    "match out on ${epair_wan}b inet from 198.51.100.0/24 nat-to (${epair_wan}b) ${option}" \
	    "pass"

	# Provoke divide by zero
	ping -c 1 192.0.2.2
	true
}

atf_test_case "no_addrs_source_hash" "cleanup"
no_addrs_source_hash_head()
{
	atf_set descr 'Test source-hash on an interface with no addresses'
	atf_set require.user root
}

no_addrs_source_hash_body()
{
	no_addrs_common "source-hash"
}

no_addrs_source_hash_cleanup()
{
	pft_cleanup
}

atf_test_case "no_addrs_random" "cleanup"
no_addrs_random_head()
{
	atf_set descr 'Test random on an interface with no addresses'
	atf_set require.user root
}

no_addrs_random_body()
{
	no_addrs_common "random"
}

no_addrs_random_cleanup()
{
	pft_cleanup
}

atf_test_case "nat_pass_in" "cleanup"
nat_pass_in_head()
{
	atf_set descr 'IPv4 NAT on inbound pass rule'
	atf_set require.user root
	atf_set require.progs scapy
}

nat_pass_in_body()
{
	setup_router_server_ipv4
	# Delete the route back to make sure that the traffic has been NAT-ed
	jexec server route del -net ${net_tester} ${net_server_host_router}
	# Provide routing back to the NAT address
	jexec server route add 203.0.113.0/24 ${net_server_host_router}
	jexec router route add 203.0.113.0/24 -iface ${epair_tester}b

	pft_set_rules router \
		"block" \
		"pass in  on ${epair_tester}b inet proto tcp nat-to 203.0.113.0 keep state" \
		"pass out on ${epair_server}a inet proto tcp keep state"

	ping_server_check_reply exit:0 --ping-type=tcp3way --send-sport=4201

	jexec router pfctl -qvvsr
	jexec router pfctl -qvvss
	jexec router ifconfig
	jexec router netstat -rn
}

nat_pass_in_cleanup()
{
	pft_cleanup
}

atf_test_case "nat_pass_out" "cleanup"
nat_pass_out_head()
{
	atf_set descr 'IPv4 NAT on outbound pass rule'
	atf_set require.user root
	atf_set require.progs scapy
}

nat_pass_out_body()
{
	setup_router_server_ipv4
	# Delete the route back to make sure that the traffic has been NAT-ed
	jexec server route del -net ${net_tester} ${net_server_host_router}

	pft_set_rules router \
		"block" \
		"pass in  on ${epair_tester}b inet proto tcp keep state" \
		"pass out on ${epair_server}a inet proto tcp nat-to ${epair_server}a keep state"

	ping_server_check_reply exit:0 --ping-type=tcp3way --send-sport=4201

	jexec router pfctl -qvvsr
	jexec router pfctl -qvvss
	jexec router ifconfig
	jexec router netstat -rn
}

nat_pass_out_cleanup()
{
	pft_cleanup
}

atf_test_case "nat_match" "cleanup"
nat_match_head()
{
	atf_set descr 'IPv4 NAT on match rule'
	atf_set require.user root
	atf_set require.progs scapy
}

nat_match_body()
{
	setup_router_server_ipv4
	# Delete the route back to make sure that the traffic has been NAT-ed
	jexec server route del -net ${net_tester} ${net_server_host_router}

	# NAT is applied during ruleset evaluation:
	# rules after "match" match on NAT-ed address
	pft_set_rules router \
		"block" \
		"pass in  on ${epair_tester}b inet proto tcp keep state" \
		"match out on ${epair_server}a inet proto tcp nat-to ${epair_server}a" \
		"pass out on ${epair_server}a inet proto tcp from ${epair_server}a keep state"

	ping_server_check_reply exit:0 --ping-type=tcp3way --send-sport=4201

	jexec router pfctl -qvvsr
	jexec router pfctl -qvvss
	jexec router ifconfig
	jexec router netstat -rn
}

nat_match_cleanup()
{
	pft_cleanup
}

map_e_common()
{
	NC_TRY_COUNT=12

	pft_init

	epair_map_e=$(vnet_mkepair)
	epair_echo=$(vnet_mkepair)

	vnet_mkjail map_e ${epair_map_e}b ${epair_echo}a
	vnet_mkjail echo ${epair_echo}b

	ifconfig ${epair_map_e}a 192.0.2.2/24 up
	route add -net 198.51.100.0/24 192.0.2.1

	jexec map_e ifconfig ${epair_map_e}b 192.0.2.1/24 up
	jexec map_e ifconfig ${epair_echo}a 198.51.100.1/24 up
	jexec map_e sysctl net.inet.ip.forwarding=1

	jexec echo ifconfig ${epair_echo}b 198.51.100.2/24 up
	jexec echo /usr/sbin/inetd -p ${PWD}/inetd-echo.pid $(atf_get_srcdir)/echo_inetd.conf

	# Enable pf!
	jexec map_e pfctl -e
}


atf_test_case "binat_match" "cleanup"
binat_match_head()
{
	atf_set descr 'IPv4 BINAT with nat ruleset'
	atf_set require.user root
	atf_set require.progs scapy
}

binat_match_body()
{
	setup_router_server_ipv4
	# Delete the route back to make sure that the traffic has been NAT-ed
	jexec server route del -net ${net_tester} ${net_server_host_router}

	# The "binat-to" rule expands to 2 rules so the ""pass" rules start at 3!
	pft_set_rules router \
		"set state-policy if-bound" \
		"set ruleset-optimization none" \
		"block" \
		"match on ${epair_server}a inet proto tcp from ${net_tester_host_tester} to any tag sometag binat-to ${epair_server}a" \
		"pass in  on ${epair_tester}b inet proto tcp !tagged sometag keep state" \
		"pass out on ${epair_server}a inet proto tcp tagged sometag keep state" \
		"pass in  on ${epair_server}a inet proto tcp tagged sometag keep state" \
		"pass out on ${epair_tester}b inet proto tcp tagged sometag keep state"

	# Test the outbound NAT part of BINAT.
	ping_server_check_reply exit:0 --ping-type=tcp3way --send-sport=4201

	states=$(mktemp) || exit 1
	jexec router pfctl -qvss | normalize_pfctl_s > $states

	for state_regexp in \
		"${epair_tester}b tcp ${net_server_host_server}:9 <- ${net_tester_host_tester}:4201 .* 3:2 pkts,.* rule 3" \
		"${epair_server}a tcp ${net_server_host_router}:4201 \(${net_tester_host_tester}:4201\) -> ${net_server_host_server}:9 .* 3:2 pkts,.* rule 4" \
	; do
		grep -qE "${state_regexp}" $states || atf_fail "State not found for '${state_regexp}'"
	done

	# Test the inbound RDR part of BINAT.
	# The "tester" becomes "server" and vice versa.
	inetd_conf=$(mktemp)
	echo "discard stream tcp nowait root internal" > $inetd_conf
	inetd -p ${PWD}/inetd_tester.pid $inetd_conf

	atf_check -s exit:0 \
	jexec server ${common_dir}/pft_ping.py \
	    --ping-type=tcp3way --send-sport=4202 \
	    --sendif ${epair_server}b \
	    --to ${net_server_host_router} \
	    --replyif ${epair_server}b

	states=$(mktemp) || exit 1
	jexec router pfctl -qvss | normalize_pfctl_s > $states

	for state_regexp in \
		"${epair_server}a tcp ${net_tester_host_tester}:9 \(${net_server_host_router}:9\) <- ${net_server_host_server}:4202 .* 3:2 pkts,.* rule 5" \
		"${epair_tester}b tcp ${net_server_host_server}:4202 -> ${net_tester_host_tester}:9 .* 3:2 pkts,.* rule 6" \
	; do
		grep -qE "${state_regexp}" $states || atf_fail "State not found for '${state_regexp}'"
	done
}

binat_match_cleanup()
{
	[ -f ${PWD}/inetd_tester.pid ] && kill $(cat ${PWD}/inetd_tester.pid)
	pft_cleanup
}

atf_test_case "empty_pool" "cleanup"
empty_pool_head()
{
	atf_set descr 'NAT with empty pool'
	atf_set require.user root
	atf_set require.progs python3 scapy
}

empty_pool_body()
{
	pft_init
	setup_router_server_ipv6


	pft_set_rules router \
		"block" \
		"pass inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv }" \
		"pass in  on ${epair_tester}b" \
		"pass out on ${epair_server}a inet6 from any to ${net_server_host_server} nat-to <nonexistent>" \

	# pf_map_addr_sn() won't be able to pick a target address, because
	# the table used in redireciton pool is empty. Packet will not be
	# forwarded, and the canonical translation failure counter increases.
	ping_server_check_reply exit:1
	# Ignore warnings about not-loaded ALTQ
	atf_check -o "match:translate +1 +" -x "jexec router pfctl -qvvsi 2> /dev/null"
}

empty_pool_cleanup()
{
	pft_cleanup
}

atf_test_case "dummynet_mask" "cleanup"
dummynet_mask_head()
{
	atf_set descr 'Verify that dummynet uses the pre-nat address for masking'
	atf_set require.user root
}

dummynet_mask_body()
{
	dummynet_init

	epair_srv=$(vnet_mkepair)
	epair_cl=$(vnet_mkepair)

	ifconfig ${epair_cl}b 192.0.2.2/24 up
	route add default 192.0.2.1

	vnet_mkjail srv ${epair_srv}a
	jexec srv ifconfig ${epair_srv}a 198.51.100.2/24 up

	vnet_mkjail gw ${epair_srv}b ${epair_cl}a
	jexec gw ifconfig ${epair_srv}b 198.51.100.1/24 up
	jexec gw ifconfig ${epair_cl}a 192.0.2.1/24 up
	jexec gw sysctl net.inet.ip.forwarding=1

	jexec gw dnctl pipe 1 config delay 100 mask src-ip 0xffffff00
	jexec gw pfctl -e
	pft_set_rules gw \
	    "match out on ${epair_srv}b inet from 192.0.2.0/24 to any nat-to (${epair_srv}b)" \
	    "pass out dnpipe 1"

	atf_check -s exit:0 -o ignore \
	    ping -c  3 198.51.100.2

	# Now check that dummynet looked at the correct address
	atf_check -s exit:0 -o match:"ip.*192.0.2.0/0" \
	    jexec gw dnctl pipe show
}

dummynet_mask_cleanup()
{
	pft_cleanup
}

atf_test_case "first_match" "cleanup"
first_match_head()
{
	atf_set descr 'Test that NAT rules are first match'
	atf_set require.user root
}

first_match_body()
{
	pft_init

	epair_nat=$(vnet_mkepair)
	epair_echo=$(vnet_mkepair)

	vnet_mkjail nat ${epair_nat}b ${epair_echo}a
	vnet_mkjail echo ${epair_echo}b

	ifconfig ${epair_nat}a 192.0.2.2/24 up
	route add -net 198.51.100.0/24 192.0.2.1

	jexec nat ifconfig ${epair_nat}b 192.0.2.1/24 up
	jexec nat ifconfig ${epair_echo}a 198.51.100.1/24 up
	jexec nat sysctl net.inet.ip.forwarding=1

	jexec echo ifconfig ${epair_echo}b 198.51.100.2/24 up

	# Match rules select translation; an explicit pass creates the state
	# needed to apply reverse translation to replies.
	jexec nat pfctl -e
	pft_set_rules nat \
		"table <foo> { 192.0.2.0/24 }" \
		"match out on ${epair_echo}a inet from <foo> to any nat-to 198.51.100.1" \
		"match out on ${epair_echo}a inet from 192.0.2.0/24 to any nat-to 198.51.100.3" \
		"pass out"

	atf_check -s exit:0 -o ignore ping -c 3 198.51.100.2
	atf_check -s exit:0 -e ignore \
	    -o match:"all icmp 198.51.100.1:.*(192.0.2.2:.*) -> 198.51.100.2:8.*" \
		jexec nat pfctl -ss
}

first_match_cleanup()
{
	pft_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "exhaust"
	atf_add_test_case "nat6_nolinklocal"
	atf_add_test_case "empty_table_source_hash"
	atf_add_test_case "no_addrs_source_hash"
	atf_add_test_case "empty_table_random"
	atf_add_test_case "no_addrs_random"
	atf_add_test_case "nat_pass_in"
	atf_add_test_case "nat_pass_out"
	atf_add_test_case "nat_match"
	atf_add_test_case "binat_match"
	atf_add_test_case "empty_pool"
	atf_add_test_case "dummynet_mask"
	atf_add_test_case "first_match"
}
