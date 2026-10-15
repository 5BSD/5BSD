#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2023 Rubicon Communications, LLC (Netgate)
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

atf_test_case "rst" "cleanup"
rst_head()
{
	atf_set descr 'Check sequence number validation in RST packets'
	atf_set require.user root
	atf_set require.progs python3 scapy
}

rst_body()
{
	pft_init
	vnet_init_bridge

	epair_srv=$(vnet_mkepair)
	epair_cl=$(vnet_mkepair)
	epair_attack=$(vnet_mkepair)

	br=$(vnet_mkbridge)
	ifconfig ${br} addm ${epair_srv}a
	ifconfig ${epair_srv}a up
	ifconfig ${br} addm ${epair_cl}a
	ifconfig ${epair_cl}a up
	ifconfig ${br} addm ${epair_attack}a
	ifconfig ${epair_attack}a up
	ifconfig ${br} up

	vnet_mkjail srv ${epair_srv}b
	jexec srv ifconfig ${epair_srv}b 192.0.2.1/24 up
	jexec srv ifconfig lo0 inet 127.0.0.1/8 up

	vnet_mkjail cl ${epair_cl}b
	jexec cl ifconfig ${epair_cl}b 192.0.2.2/24 up
	jexec cl ifconfig lo0 inet 127.0.0.1/8 up

	jexec cl pfctl -e
	pft_set_rules cl \
		"pass keep state"

	# Not required, but pf should log the bad RST packet with this set.
	jexec cl pfctl -x loud

	vnet_mkjail attack ${epair_attack}b
	jexec attack ifconfig ${epair_attack}b 192.0.2.3/24 up

	# Sanity check
	atf_check -s exit:0 -o ignore \
	    jexec cl ping -c 1 192.0.2.1

	echo "bar" | jexec srv nc -l 1234 &
	# Allow server time to start
	sleep 1

	echo "foo" | jexec cl nc -p 4321 192.0.2.1 1234 &
	# Allow connection time to set up
	sleep 1

	# Connection should be established now
	atf_check -s exit:0 -e ignore \
	    -o match:"ESTABLISHED:ESTABLISHED" \
	    jexec cl pfctl -ss -v

	# Now insert a fake RST
	atf_check -s exit:0 -o ignore \
	    jexec attack ${common_dir}/pft_rst.py 192.0.2.1 1234 192.0.2.2 4321

	# Connection should remain established
	atf_check -s exit:0 -e ignore \
	    -o match:"ESTABLISHED:ESTABLISHED" \
	    jexec cl pfctl -ss -v
}

rst_cleanup()
{
	pft_cleanup
}

original_ack_test()
{
	family=$1
	pft_init
	left=$(vnet_mkepair)
	right=$(vnet_mkepair)
	vnet_mkjail router ${left}b ${right}b
	if [ "$family" = inet ]; then
		lp=192.0.2.; rp=198.51.100.; mask=24
		forwarding=net.inet.ip.forwarding
	else
		lp=2001:db8:1::; rp=2001:db8:2::; mask=64
		forwarding=net.inet6.ip6.forwarding
	fi
	ifconfig ${left}a $family ${lp}1/$mask up
	ifconfig ${right}a $family ${rp}1/$mask up
	jexec router ifconfig ${left}b $family ${lp}2/$mask up
	jexec router ifconfig ${right}b $family ${rp}2/$mask up
	sysctl $forwarding=0
	jexec router sysctl $forwarding=1
	if [ "$family" = inet6 ]; then
		while { ifconfig; jexec router ifconfig; } | grep -q tentative; do sleep 1; done
	fi
	left_mac=$(ifconfig ${left}a | awk '/ether/ { print $2 }')
	right_mac=$(ifconfig ${right}a | awk '/ether/ { print $2 }')
	if [ "$family" = inet ]; then
		jexec router arp -s ${lp}10 "$left_mac"
		jexec router arp -s ${rp}20 "$right_mac"
	else
		jexec router ndp -s ${lp}10 "$left_mac"
		jexec router ndp -s ${rp}20 "$right_mac"
	fi
	left_mac=$(jexec router ifconfig ${left}b | awk '/ether/ { print $2 }')
	right_mac=$(jexec router ifconfig ${right}b | awk '/ether/ { print $2 }')
	jexec router pfctl -e
	# One filtering interface makes this a single stateful firewall boundary.
	# Only SYN may create a state; resets cannot fall through to a permissive
	# rule and create a replacement state after the tracking check rejects them.
	pft_set_rules router "set skip on ${right}b" 'block' \
	    "pass in quick on ${left}b $family proto tcp from ${lp}10 to ${rp}20 flags S/SA keep state"
	atf_check -s exit:0 -o match:'ORIGINAL_ACK_CASE.*wrap_zero passed' -e ignore \
	    python3 $(atf_get_srcdir)/tcp-original-ack.py --family "$family" \
	    --left ${left}a --right ${right}a --left-mac "$left_mac" \
	    --right-mac "$right_mac" --jail router
}

atf_test_case "original_ack_v4" "cleanup"
original_ack_v4_head()
{
	atf_set descr 'TCP RST original ACK validation and state survival (inet)'
	atf_set require.user root
	atf_set require.progs 'python3 scapy'
	atf_set timeout 600
}
original_ack_v4_body()
{
	original_ack_test inet
}
original_ack_v4_cleanup()
{
	pft_cleanup
}

atf_test_case "original_ack_v6" "cleanup"
original_ack_v6_head()
{
	atf_set descr 'TCP RST original ACK validation and state survival (inet6)'
	atf_set require.user root
	atf_set require.progs 'python3 scapy'
	atf_set timeout 600
}
original_ack_v6_body()
{
	original_ack_test inet6
}
original_ack_v6_cleanup()
{
	pft_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "original_ack_v4"
	atf_add_test_case "original_ack_v6"
	atf_add_test_case "rst"
}
