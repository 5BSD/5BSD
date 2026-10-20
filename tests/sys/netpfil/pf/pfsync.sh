#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2018 Orange Business Services
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

atf_test_case "basic" "cleanup"
basic_head()
{
	atf_set descr 'Basic pfsync test'
	atf_set require.user root
}

basic_body()
{
	common_body
}

common_body()
{
	defer=$1
	pfsynct_init

	epair_sync=$(vnet_mkepair)
	epair_one=$(vnet_mkepair)
	epair_two=$(vnet_mkepair)

	vnet_mkjail one ${epair_one}a ${epair_sync}a
	vnet_mkjail two ${epair_two}a ${epair_sync}b
	pfsynct_mkif one
	pfsynct_mkif two

	# pfsync interface
	jexec one ifconfig ${epair_sync}a 192.0.2.1/24 up
	jexec one ifconfig ${epair_one}a 198.51.100.1/24 up
	jexec one ifconfig pfsync0 \
		syncdev ${epair_sync}a \
		maxupd 1 \
		$defer \
		up
	jexec two ifconfig ${epair_two}a 198.51.100.2/24 up
	jexec two ifconfig ${epair_sync}b 192.0.2.2/24 up
	jexec two ifconfig pfsync0 \
		syncdev ${epair_sync}b \
		maxupd 1 \
		$defer \
		up

	# Enable pf!
	jexec one pfctl -e
	pft_set_rules one \
		"set skip on ${epair_sync}a" \
		"pass out keep state"
	jexec two pfctl -e
	pft_set_rules two \
		"set skip on ${epair_sync}b" \
		"pass out keep state"

	hostid_one=$(jexec one pfctl -si -v | awk '/Hostid:/ { gsub(/0x/, "", $2); printf($2); }')

	ifconfig ${epair_one}b 198.51.100.254/24 up

	# OpenBSD pf creates no state for an outbound ICMP echo reply, so
	# originate the echo request behind the "pass out keep state" rule.
	jexec one ping -c 1 -S 198.51.100.1 198.51.100.254

	# Give pfsync time to do its thing
	sleep 2

	if ! jexec two pfctl -s states | grep icmp | grep 198.51.100.1 | \
	    grep 198.51.100.254 ; then
		atf_fail "state not found on synced host"
	fi

	# OpenBSD pfctl has no -sc; check the synced state's creator instead.
	if ! jexec two pfctl -ss -vv | grep "creatorid: ${hostid_one}";
	then
		jexec two pfctl -ss -vv
		atf_fail "HostID for host one not found on two"
	fi
}

basic_cleanup()
{
	pfsynct_cleanup
}

atf_test_case "basic_defer" "cleanup"
basic_defer_head()
{
	atf_set descr 'Basic defer mode pfsync test'
	atf_set require.user root
}

basic_defer_body()
{
	common_body defer
}

basic_defer_cleanup()
{
	pfsynct_cleanup
}

atf_test_case "defer" "cleanup"
defer_head()
{
	atf_set descr 'Defer mode pfsync test'
	atf_set require.user root
	atf_set require.progs python3 scapy
}

defer_body()
{
	pfsynct_init

	epair_sync=$(vnet_mkepair)
	epair_in=$(vnet_mkepair)
	epair_out=$(vnet_mkepair)

	vnet_mkjail alcatraz ${epair_sync}a ${epair_in}a ${epair_out}a
	pfsynct_mkif alcatraz

	jexec alcatraz ifconfig ${epair_sync}a 192.0.2.1/24 up
	jexec alcatraz ifconfig ${epair_out}a 198.51.100.1/24 up
	jexec alcatraz ifconfig ${epair_in}a 203.0.113.1/24 up
	jexec alcatraz arp -s 203.0.113.2 00:01:02:03:04:05
	jexec alcatraz sysctl net.inet.ip.forwarding=1

	jexec alcatraz ifconfig pfsync0 \
		syncdev ${epair_sync}a \
		maxupd 1 \
		defer \
		up

	ifconfig ${epair_sync}b 192.0.2.2/24 up
	ifconfig ${epair_out}b 198.51.100.2/24 up
	ifconfig ${epair_in}b up
	route add -net 203.0.113.0/24 198.51.100.1

	# Enable pf
	jexec alcatraz pfctl -e
	pft_set_rules alcatraz \
		"set skip on ${epair_sync}a" \
		"pass keep state"

	atf_check -s exit:0 env PYTHONPATH=${common_dir} \
		$(atf_get_srcdir)/pfsync_defer.py \
		--syncdev ${epair_sync}b \
		--indev ${epair_in}b \
		--outdev ${epair_out}b

	# Now disable defer mode and expect failure.
	jexec alcatraz ifconfig pfsync0 -defer

	# Flush state
	pft_set_rules alcatraz \
		"set skip on ${epair_sync}a" \
		"pass keep state"

	atf_check -s exit:3 env PYTHONPATH=${common_dir} \
		$(atf_get_srcdir)/pfsync_defer.py \
		--syncdev ${epair_sync}b \
		--indev ${epair_in}b \
		--outdev ${epair_out}b
}

defer_cleanup()
{
	pfsynct_cleanup
}

atf_test_case "bulk" "cleanup"
bulk_head()
{
	atf_set descr 'Test bulk updates'
	atf_set require.user root
}

bulk_body()
{
	pfsynct_init

	epair_sync=$(vnet_mkepair)
	epair_one=$(vnet_mkepair)
	epair_two=$(vnet_mkepair)

	vnet_mkjail one ${epair_one}a ${epair_sync}a
	vnet_mkjail two ${epair_two}a ${epair_sync}b
	pfsynct_mkif one
	pfsynct_mkif two

	# pfsync interface
	jexec one ifconfig ${epair_sync}a 192.0.2.1/24 up
	jexec one ifconfig ${epair_sync}a mtu 9000
	jexec one ifconfig ${epair_one}a 198.51.100.1/24 up
	jexec one ifconfig pfsync0 \
		syncdev ${epair_sync}a \
		up mtu 9000
	jexec two ifconfig ${epair_two}a 198.51.100.2/24 up
	jexec two ifconfig ${epair_sync}b 192.0.2.2/24 up
	jexec two ifconfig ${epair_sync}b mtu 9000

	# Enable pf
	jexec one pfctl -e
	pft_set_rules one \
		"set skip on ${epair_sync}a" \
		"pass keep state"
	jexec two pfctl -e
	pft_set_rules two \
		"set skip on ${epair_sync}b" \
		"pass keep state"

	ifconfig ${epair_one}b 198.51.100.254/24 up

	# Create states prior to setting up pfsync
	${common_dir}/pft_synflood.py \
		--sendif ${epair_one}b \
		--to 198.51.100.1 \
		--count 500
	ping -c 1 -S 198.51.100.254 198.51.100.1

	# Wait before setting up pfsync on two, so we don't accidentally catch
	# the update anyway.
	sleep 1

	# Now set up pfsync in jail two
	jexec two ifconfig pfsync0 \
		syncdev ${epair_sync}b \
		up

	# Give pfsync time to do its thing
	sleep 2

	jexec two pfctl -s states
	if ! jexec two pfctl -s states | grep icmp | grep 198.51.100.1 | \
	    grep 198.51.100.2 ; then
		atf_fail "state not found on synced host"
	fi
}

bulk_cleanup()
{
	pfsynct_cleanup
}

atf_test_case "pbr" "cleanup"
pbr_head()
{
	atf_set descr 'route_to and reply_to directives test'
	atf_set require.user root
	atf_set timeout '600'
}

pbr_body()
{
	pbr_common_body
}

pbr_cleanup()
{
	pbr_common_cleanup
}

atf_test_case "pfsync_pbr" "cleanup"
pfsync_pbr_head()
{
	atf_set descr 'route_to and reply_to directives pfsync test'
	atf_set require.user root
	atf_set timeout '600'
}

pfsync_pbr_body()
{
	pbr_common_body backup_promotion
}

pfsync_pbr_cleanup()
{
	pbr_common_cleanup
}

pbr_common_body()
{
	# + builds bellow topology and initiate a single ping session
	#   from client to server.
	# + gw* forward traffic through pbr not fib lookups.
	# + if backup_promotion arg is given, a carp failover event occurs
	#   during the ping session on both gateways.
	#                   ┌──────┐
	#                   │client│
	#                   └───┬──┘
	#                       │
	#                   ┌───┴───┐
	#                   │bridge0│
	#                   └┬─────┬┘
	#                    │     │
	#   ┌────────────────┴─┐ ┌─┴────────────────┐
	#   │gw_route_to_master├─┤gw_route_to_backup│
	#   └────────────────┬─┘ └─┬────────────────┘
	#                    │     │
	#                   ┌┴─────┴┐
	#                   │bridge1│
	#                   └┬─────┬┘
	#                    │     │
	#   ┌────────────────┴─┐ ┌─┴────────────────┐
	#   │gw_reply_to_master├─┤gw_reply_to_backup│
	#   └────────────────┬─┘ └─┬────────────────┘
	#                    │     │
	#                   ┌┴─────┴┐
	#                   │bridge2│
	#                   └───┬───┘
	#                       │
	#                   ┌───┴──┐
	#                   │server│
	#                   └──────┘

	if ! kldstat -q -m carp
	then
		atf_skip "This test requires carp"
	fi
	pfsynct_init
	vnet_init_bridge

	bridge0=$(vnet_mkbridge)
	bridge1=$(vnet_mkbridge)
	bridge2=$(vnet_mkbridge)

	epair_sync_gw_route_to=$(vnet_mkepair)
	epair_sync_gw_reply_to=$(vnet_mkepair)
	epair_client_bridge0=$(vnet_mkepair)

	epair_gw_route_to_master_bridge0=$(vnet_mkepair)
	epair_gw_route_to_backup_bridge0=$(vnet_mkepair)
	epair_gw_route_to_master_bridge1=$(vnet_mkepair)
	epair_gw_route_to_backup_bridge1=$(vnet_mkepair)

	epair_gw_reply_to_master_bridge1=$(vnet_mkepair)
	epair_gw_reply_to_backup_bridge1=$(vnet_mkepair)
	epair_gw_reply_to_master_bridge2=$(vnet_mkepair)
	epair_gw_reply_to_backup_bridge2=$(vnet_mkepair)

	epair_server_bridge2=$(vnet_mkepair)

	ifconfig ${bridge0} up
	ifconfig ${epair_client_bridge0}b up
	ifconfig ${epair_gw_route_to_master_bridge0}b up
	ifconfig ${epair_gw_route_to_backup_bridge0}b up
	ifconfig ${bridge0} \
		addm ${epair_client_bridge0}b \
		addm ${epair_gw_route_to_master_bridge0}b \
		addm ${epair_gw_route_to_backup_bridge0}b

	ifconfig ${bridge1} up
	ifconfig ${epair_gw_route_to_master_bridge1}b up
	ifconfig ${epair_gw_route_to_backup_bridge1}b up
	ifconfig ${epair_gw_reply_to_master_bridge1}b up
	ifconfig ${epair_gw_reply_to_backup_bridge1}b up
	ifconfig ${bridge1} \
		addm ${epair_gw_route_to_master_bridge1}b \
		addm ${epair_gw_route_to_backup_bridge1}b \
		addm ${epair_gw_reply_to_master_bridge1}b \
		addm ${epair_gw_reply_to_backup_bridge1}b

	ifconfig ${bridge2} up
	ifconfig ${epair_gw_reply_to_master_bridge2}b up
	ifconfig ${epair_gw_reply_to_backup_bridge2}b up
	ifconfig ${epair_server_bridge2}b up
	ifconfig ${bridge2} \
		addm ${epair_gw_reply_to_master_bridge2}b \
		addm ${epair_gw_reply_to_backup_bridge2}b \
		addm ${epair_server_bridge2}b

	vnet_mkjail client ${epair_client_bridge0}a
	jexec client hostname client
	vnet_mkjail gw_route_to_master \
		${epair_gw_route_to_master_bridge0}a \
		${epair_gw_route_to_master_bridge1}a \
		${epair_sync_gw_route_to}a
	jexec gw_route_to_master hostname gw_route_to_master
	vnet_mkjail gw_route_to_backup \
		${epair_gw_route_to_backup_bridge0}a \
		${epair_gw_route_to_backup_bridge1}a \
		${epair_sync_gw_route_to}b
	jexec gw_route_to_backup hostname gw_route_to_backup
	vnet_mkjail gw_reply_to_master \
		${epair_gw_reply_to_master_bridge1}a \
		${epair_gw_reply_to_master_bridge2}a \
		${epair_sync_gw_reply_to}a
	jexec gw_reply_to_master hostname gw_reply_to_master
	vnet_mkjail gw_reply_to_backup \
		${epair_gw_reply_to_backup_bridge1}a \
		${epair_gw_reply_to_backup_bridge2}a \
		${epair_sync_gw_reply_to}b
	jexec gw_reply_to_backup hostname gw_reply_to_backup
	vnet_mkjail server ${epair_server_bridge2}a
	jexec server hostname server
	pfsynct_mkif gw_route_to_master
	pfsynct_mkif gw_route_to_backup
	pfsynct_mkif gw_reply_to_master
	pfsynct_mkif gw_reply_to_backup

	jexec client ifconfig ${epair_client_bridge0}a inet 198.18.0.1/24 up
	jexec client route add 198.18.2.0/24 198.18.0.10

	jexec gw_route_to_master ifconfig ${epair_sync_gw_route_to}a \
		inet 198.19.10.1/24 up
	jexec gw_route_to_master ifconfig ${epair_gw_route_to_master_bridge0}a \
		inet 198.18.0.8/24 up
	jexec gw_route_to_master ifconfig ${epair_gw_route_to_master_bridge0}a \
		alias 198.18.0.10/32 vhid 10 pass 3WjvVVw7 advskew 50
	jexec gw_route_to_master ifconfig ${epair_gw_route_to_master_bridge1}a \
		inet 198.18.1.8/24 up
	jexec gw_route_to_master ifconfig ${epair_gw_route_to_master_bridge1}a \
		alias 198.18.1.10/32 vhid 11 pass 3WjvVVw7 advskew 50
	jexec gw_route_to_master sysctl net.inet.ip.forwarding=1
	jexec gw_route_to_master sysctl net.inet.carp.preempt=1

	vnet_ifrename_jail gw_route_to_master ${epair_sync_gw_route_to}a if_pfsync
	vnet_ifrename_jail gw_route_to_master ${epair_gw_route_to_master_bridge0}a if_br0
	vnet_ifrename_jail gw_route_to_master ${epair_gw_route_to_master_bridge1}a if_br1

	jexec gw_route_to_master ifconfig pfsync0 \
		syncpeer 198.19.10.2 \
		syncdev if_pfsync \
		maxupd 1 \
		up
	pft_set_rules gw_route_to_master \
		"keep_state = 'tag auth_packet keep state'" \
		"set timeout { icmp.first 120, icmp.error 60 }" \
		"block log all" \
		"pass quick on if_pfsync proto pfsync keep state (no-sync)" \
		"pass quick on { if_br0 if_br1 } proto carp keep state (no-sync)" \
		"block drop in quick to 224.0.0.18/32" \
		"pass out quick tagged auth_packet keep state" \
		"pass in quick log on if_br0 proto { icmp udp tcp } from 198.18.0.0/24 to 198.18.2.0/24 route-to 198.18.1.20 \$keep_state"
	jexec gw_route_to_master pfctl -e

	jexec gw_route_to_backup ifconfig ${epair_sync_gw_route_to}b \
		inet 198.19.10.2/24 up
	jexec gw_route_to_backup ifconfig ${epair_gw_route_to_backup_bridge0}a \
		inet 198.18.0.9/24 up
	jexec gw_route_to_backup ifconfig ${epair_gw_route_to_backup_bridge0}a \
		alias 198.18.0.10/32 vhid 10 pass 3WjvVVw7 advskew 100
	jexec gw_route_to_backup ifconfig ${epair_gw_route_to_backup_bridge1}a \
		inet 198.18.1.9/24 up
	jexec gw_route_to_backup ifconfig ${epair_gw_route_to_backup_bridge1}a \
		alias 198.18.1.10/32 vhid 11 pass 3WjvVVw7 advskew 100
	jexec gw_route_to_backup sysctl net.inet.ip.forwarding=1
	jexec gw_route_to_backup sysctl net.inet.carp.preempt=1

	vnet_ifrename_jail gw_route_to_backup ${epair_sync_gw_route_to}b if_pfsync
	vnet_ifrename_jail gw_route_to_backup ${epair_gw_route_to_backup_bridge0}a if_br0
	vnet_ifrename_jail gw_route_to_backup ${epair_gw_route_to_backup_bridge1}a if_br1

	jexec gw_route_to_backup ifconfig pfsync0 \
		syncpeer 198.19.10.1 \
		syncdev if_pfsync \
		up
	pft_set_rules gw_route_to_backup \
		"keep_state = 'tag auth_packet keep state'" \
		"set timeout { icmp.first 120, icmp.error 60 }" \
		"block log all" \
		"pass quick on if_pfsync proto pfsync keep state (no-sync)" \
		"pass quick on { if_br0 if_br1 } proto carp keep state (no-sync)" \
		"block drop in quick to 224.0.0.18/32" \
		"pass out quick tagged auth_packet keep state" \
		"pass in quick log on if_br0 proto { icmp udp tcp } from 198.18.0.0/24 to 198.18.2.0/24 route-to 198.18.1.20 \$keep_state"
	jexec gw_route_to_backup pfctl -e

	jexec gw_reply_to_master ifconfig ${epair_sync_gw_reply_to}a \
		inet 198.19.20.1/24 up
	jexec gw_reply_to_master ifconfig ${epair_gw_reply_to_master_bridge1}a \
		inet 198.18.1.18/24 up
	jexec gw_reply_to_master ifconfig ${epair_gw_reply_to_master_bridge1}a \
		alias 198.18.1.20/32 vhid 21 pass 3WjvVVw7 advskew 50
	jexec gw_reply_to_master ifconfig ${epair_gw_reply_to_master_bridge2}a \
		inet 198.18.2.18/24 up
	jexec gw_reply_to_master ifconfig ${epair_gw_reply_to_master_bridge2}a \
		alias 198.18.2.20/32 vhid 22 pass 3WjvVVw7 advskew 50
	jexec gw_reply_to_master sysctl net.inet.ip.forwarding=1
	jexec gw_reply_to_master sysctl net.inet.carp.preempt=1

	vnet_ifrename_jail gw_reply_to_master ${epair_sync_gw_reply_to}a if_pfsync
	vnet_ifrename_jail gw_reply_to_master ${epair_gw_reply_to_master_bridge1}a if_br1
	vnet_ifrename_jail gw_reply_to_master ${epair_gw_reply_to_master_bridge2}a if_br2

	jexec gw_reply_to_master ifconfig pfsync0 \
		syncpeer 198.19.20.2 \
		syncdev if_pfsync \
		maxupd 1 \
		up
	pft_set_rules gw_reply_to_master \
		"set timeout { icmp.first 120, icmp.error 60 }" \
		"block log all" \
		"pass quick on if_pfsync proto pfsync keep state (no-sync)" \
		"pass quick on { if_br1 if_br2 } proto carp keep state (no-sync)" \
		"block drop in quick to 224.0.0.18/32" \
		"pass out quick on if_br2 tagged auth_packet_reply_to reply-to 198.18.1.10 keep state" \
		"pass in quick log on if_br1 proto { icmp udp tcp } from 198.18.0.0/24 to 198.18.2.0/24 tag auth_packet_reply_to keep state"
	jexec gw_reply_to_master pfctl -e

	jexec gw_reply_to_backup ifconfig ${epair_sync_gw_reply_to}b \
		inet 198.19.20.2/24 up
	jexec gw_reply_to_backup ifconfig ${epair_gw_reply_to_backup_bridge1}a \
		inet 198.18.1.19/24 up
	jexec gw_reply_to_backup ifconfig ${epair_gw_reply_to_backup_bridge1}a \
		alias 198.18.1.20/32 vhid 21 pass 3WjvVVw7 advskew 100
	jexec gw_reply_to_backup ifconfig ${epair_gw_reply_to_backup_bridge2}a \
		inet 198.18.2.19/24 up
	jexec gw_reply_to_backup ifconfig ${epair_gw_reply_to_backup_bridge2}a \
		alias 198.18.2.20/32 vhid 22 pass 3WjvVVw7 advskew 100
	jexec gw_reply_to_backup sysctl net.inet.ip.forwarding=1
	jexec gw_reply_to_backup sysctl net.inet.carp.preempt=1

	vnet_ifrename_jail gw_reply_to_backup ${epair_sync_gw_reply_to}b if_pfsync
	vnet_ifrename_jail gw_reply_to_backup ${epair_gw_reply_to_backup_bridge1}a if_br1
	vnet_ifrename_jail gw_reply_to_backup ${epair_gw_reply_to_backup_bridge2}a if_br2

	jexec gw_reply_to_backup ifconfig pfsync0 \
		syncpeer 198.19.20.1 \
		syncdev if_pfsync \
		up
	pft_set_rules gw_reply_to_backup \
		"set timeout { icmp.first 120, icmp.error 60 }" \
		"block log all" \
		"pass quick on if_pfsync proto pfsync keep state (no-sync)" \
		"pass quick on { if_br1 if_br2 } proto carp keep state (no-sync)" \
		"block drop in quick to 224.0.0.18/32" \
		"pass out quick on if_br2 tagged auth_packet_reply_to reply-to 198.18.1.10 keep state" \
		"pass in quick log on if_br1 proto { icmp udp tcp } from 198.18.0.0/24 to 198.18.2.0/24 tag auth_packet_reply_to keep state"
	jexec gw_reply_to_backup pfctl -e

	jexec server ifconfig ${epair_server_bridge2}a inet 198.18.2.1/24 up
	jexec server route add 198.18.0.0/24 198.18.2.20

	# Waiting for platform to settle
	while ! jexec gw_route_to_backup ifconfig | grep 'carp: BACKUP'
	do
		sleep 1
	done
	while ! jexec gw_reply_to_backup ifconfig | grep 'carp: BACKUP'
	do
		sleep 1
	done
	while ! jexec client ping -c 10 198.18.2.1 | grep ', 0.0% packet loss'
	do
		sleep 1
	done

	# Checking cluster members pf.conf checksums match
	gw_route_to_master_checksum=$(jexec gw_route_to_master pfctl -si -v | grep 'Checksum:' | cut -d ' ' -f 2)
	gw_route_to_backup_checksum=$(jexec gw_route_to_backup pfctl -si -v | grep 'Checksum:' | cut -d ' ' -f 2)
	gw_reply_to_master_checksum=$(jexec gw_reply_to_master pfctl -si -v | grep 'Checksum:' | cut -d ' ' -f 2)
	gw_reply_to_backup_checksum=$(jexec gw_reply_to_backup pfctl -si -v | grep 'Checksum:' | cut -d ' ' -f 2)
	if [ "$gw_route_to_master_checksum" != "$gw_route_to_backup_checksum" ]
	then
		atf_fail "gw_route_to cluster members pf.conf do not match each others"
	fi
	if [ "$gw_reply_to_master_checksum" != "$gw_reply_to_backup_checksum" ]
	then
		atf_fail "gw_reply_to cluster members pf.conf do not match each others"
	fi

	# Creating state entries
	(jexec client ping -c 10 198.18.2.1 >ping.stdout) &

	if [ "$1" = "backup_promotion" ]
	then
		sleep 1
		jexec gw_route_to_backup ifconfig if_br0 vhid 10 advskew 0
		jexec gw_route_to_backup ifconfig if_br1 vhid 11 advskew 0
		jexec gw_reply_to_backup ifconfig if_br1 vhid 21 advskew 0
		jexec gw_reply_to_backup ifconfig if_br2 vhid 22 advskew 0
	fi
	while ! grep -q -e 'packet loss' ping.stdout
	do
		sleep 1
	done

	atf_check -s exit:0 -e ignore -o ignore grep ', 0.0% packet loss' ping.stdout
}

pbr_common_cleanup()
{
	pft_cleanup
}

atf_test_case "ipsec" "cleanup"
ipsec_head()
{
	atf_set descr 'Transport pfsync over IPSec'
	atf_set require.user root
}

ipsec_body()
{
	if ! sysctl -q kern.features.ipsec >/dev/null ; then
		atf_skip "This test requires ipsec"
	fi

	# Run the common test, to set up pfsync
	common_body

	# But we want unicast pfsync.  As on OpenBSD, the peer of a running
	# pfsync interface cannot change (EBUSY): take it down first.
	atf_check jexec one ifconfig pfsync0 down syncpeer 192.0.2.2 up
	atf_check jexec two ifconfig pfsync0 down syncpeer 192.0.2.1 up

	# Flush existing states
	jexec one pfctl -Fs
	jexec two pfctl -Fs

	# Now define an ipsec policy to run over the epair_sync interfaces
	echo "flush;
	spdflush;
	spdadd 192.0.2.1/32 192.0.2.2/32 any -P out ipsec esp/transport//require;
	spdadd 192.0.2.2/32 192.0.2.1/32 any -P in ipsec esp/transport//require;
	add 192.0.2.1 192.0.2.2 esp 0x1000 -E aes-gcm-16 \"12345678901234567890\";
	add 192.0.2.2 192.0.2.1 esp 0x1001 -E aes-gcm-16 \"12345678901234567890\";" \
	    | jexec one setkey -c

	echo "flush;
	spdflush;
	spdadd 192.0.2.2/32 192.0.2.1/32 any -P out ipsec esp/transport//require;
	spdadd 192.0.2.1/32 192.0.2.2/32 any -P in ipsec esp/transport//require;
	add 192.0.2.1 192.0.2.2 esp 0x1000 -E aes-gcm-16 \"12345678901234567891\";
	add 192.0.2.2 192.0.2.1 esp 0x1001 -E aes-gcm-16 \"12345678901234567891\";" \
	    | jexec two setkey -c

	# We've set incompatible keys, so pfsync will be broken.
	jexec one ping -c 1 -S 198.51.100.1 198.51.100.254

	# Give pfsync time to do its thing
	sleep 2

	if jexec two pfctl -s states | grep icmp | grep 198.51.100.1 | \
	    grep 198.51.100.2 ; then
		atf_fail "state synced although IPSec should have prevented it"
	fi

	# Flush existing states
	jexec one pfctl -Fs
	jexec two pfctl -Fs

	# Fix the IPSec key to match
	echo "flush;
	spdflush;
	spdadd 192.0.2.2/32 192.0.2.1/32 any -P out ipsec esp/transport//require;
	spdadd 192.0.2.1/32 192.0.2.2/32 any -P in ipsec esp/transport//require;
	add 192.0.2.1 192.0.2.2 esp 0x1000 -E aes-gcm-16 \"12345678901234567890\";
	add 192.0.2.2 192.0.2.1 esp 0x1001 -E aes-gcm-16 \"12345678901234567890\";" \
	    | jexec two setkey -c

	jexec one ping -c 1 -S 198.51.100.1 198.51.100.254

	# Give pfsync time to do its thing
	sleep 2

	if ! jexec two pfctl -s states | grep icmp | grep 198.51.100.1 | \
	    grep 198.51.100.2 ; then
		atf_fail "state not found on synced host"
	fi
}

ipsec_cleanup()
{
	pft_cleanup
}

atf_test_case "timeout" "cleanup"
timeout_head()
{
	atf_set descr 'Trigger pfsync_timeout()'
	atf_set require.user root
}

timeout_body()
{
	pfsynct_init

	vnet_mkjail one
	pfsynct_mkif one

	jexec one ifconfig lo0 127.0.0.1/8 up
	jexec one ifconfig lo0 inet6 ::1/128 up

	pft_set_rules one \
		"pass all"
	jexec one pfctl -e
	jexec one ifconfig pfsync0 defer up

	jexec one ping -c 1 ::1
	jexec one ping -c 1 127.0.0.1

	# Give pfsync_timeout() time to fire (a callout on a 1 second delay)
	sleep 2
}

timeout_cleanup()
{
	pft_cleanup
}

atf_test_case "basic_ipv6_unicast" "cleanup"
basic_ipv6_unicast_head()
{
	atf_set descr 'Basic pfsync test (IPv6)'
	atf_set require.user root
}

basic_ipv6_unicast_body()
{
	pfsynct_init

	epair_sync=$(vnet_mkepair)
	epair_one=$(vnet_mkepair)
	epair_two=$(vnet_mkepair)

	vnet_mkjail one ${epair_one}a ${epair_sync}a
	vnet_mkjail two ${epair_two}a ${epair_sync}b
	pfsynct_mkif one
	pfsynct_mkif two

	# pfsync interface
	jexec one ifconfig ${epair_sync}a inet6 fd2c::1/64 no_dad up
	jexec one ifconfig ${epair_one}a inet6 fd2b::1/64 no_dad up
	jexec one ifconfig pfsync0 \
		syncdev ${epair_sync}a \
		syncpeer fd2c::2 \
		maxupd 1 \
		up
	jexec two ifconfig ${epair_two}a inet6 fd2b::2/64 no_dad up
	jexec two ifconfig ${epair_sync}b inet6 fd2c::2/64 no_dad up
	jexec two ifconfig pfsync0 \
		syncdev ${epair_sync}b \
		syncpeer fd2c::1 \
		maxupd 1 \
		up

	# Enable pf!
	jexec one pfctl -e
	pft_set_rules one \
		"block on ${epair_sync}a inet" \
		"pass out keep state"
	jexec two pfctl -e
	pft_set_rules two \
		"block on ${epair_sync}b inet" \
		"pass out keep state"

	ifconfig ${epair_one}b inet6 fd2b::f0/64 no_dad up

	jexec one ping6 -c 1 -S fd2b::1 fd2b::f0

	# Give pfsync time to do its thing
	sleep 2

	if ! jexec two pfctl -s states | grep icmp | grep fd2b::1 | \
	    grep fd2b::f0 ; then
		atf_fail "state not found on synced host"
	fi
}

basic_ipv6_unicast_cleanup()
{
	pfsynct_cleanup
}

atf_test_case "basic_ipv6" "cleanup"
basic_ipv6_head()
{
	atf_set descr 'Basic pfsync test (IPv6)'
	atf_set require.user root
}

basic_ipv6_body()
{
	pfsynct_init

	epair_sync=$(vnet_mkepair)
	epair_one=$(vnet_mkepair)
	epair_two=$(vnet_mkepair)

	vnet_mkjail one ${epair_one}a ${epair_sync}a
	vnet_mkjail two ${epair_two}a ${epair_sync}b
	pfsynct_mkif one
	pfsynct_mkif two

	# pfsync interface
	jexec one ifconfig ${epair_sync}a inet6 fd2c::1/64 no_dad up
	jexec one ifconfig ${epair_one}a inet6 fd2b::1/64 no_dad up
	jexec one ifconfig pfsync0 \
		syncdev ${epair_sync}a \
		syncpeer ff12::f0 \
		maxupd 1 \
		up
	jexec two ifconfig ${epair_two}a inet6 fd2b::2/64 no_dad up
	jexec two ifconfig ${epair_sync}b inet6 fd2c::2/64 no_dad up
	jexec two ifconfig pfsync0 \
		syncdev ${epair_sync}b \
		syncpeer ff12::f0 \
		maxupd 1 \
		up

	# Enable pf!
	jexec one pfctl -e
	pft_set_rules one \
		"block on ${epair_sync}a inet" \
		"pass out keep state"
	jexec two pfctl -e
	pft_set_rules two \
		"block on ${epair_sync}b inet" \
		"pass out keep state"

	ifconfig ${epair_one}b inet6 fd2b::f0/64 no_dad up

	jexec one ping6 -c 1 -S fd2b::1 fd2b::f0

	# Give pfsync time to do its thing
	sleep 2

	if ! jexec two pfctl -s states | grep icmp | grep fd2b::1 | \
	    grep fd2b::f0 ; then
		atf_fail "state not found on synced host"
	fi
}

basic_ipv6_cleanup()
{
	pfsynct_cleanup
}

atf_test_case "rtable" "cleanup"
rtable_head()
{
	atf_set descr 'Test handling of invalid rtableid'
	atf_set require.user root
}

rtable_body()
{
	pfsynct_init

	epair_sync=$(vnet_mkepair)
	epair_one=$(vnet_mkepair)
	epair_two=$(vnet_mkepair)

	vnet_mkjail one ${epair_one}a ${epair_sync}a
	vnet_mkjail two ${epair_two}a ${epair_sync}b
	pfsynct_mkif one
	pfsynct_mkif two

	# pfsync interface
	jexec one ifconfig ${epair_sync}a 192.0.2.1/24 up
	jexec one ifconfig ${epair_one}a 198.51.100.1/24 up
	jexec one ifconfig pfsync0 \
		syncdev ${epair_sync}a \
		maxupd 1 \
		up
	jexec two ifconfig ${epair_two}a 198.51.100.1/24 up
	jexec two ifconfig ${epair_sync}b 192.0.2.2/24 up
	jexec two ifconfig pfsync0 \
		syncdev ${epair_sync}b \
		maxupd 1 \
		up

	# Make life easy, give ${epair_two}a the same mac addrss as ${epair_one}a
	mac=$(jexec one ifconfig ${epair_one}a | awk '/lladdr/ { print($2); }')
	jexec two ifconfig ${epair_two}a ether ${mac}

	# Enable pf!
	jexec one /sbin/sysctl net.fibs=8
	jexec one pfctl -e
	pft_set_rules one \
		"set skip on ${epair_sync}a" \
		"pass rtable 3 keep state"
	# No extra fibs in two
	jexec two pfctl -e
	pft_set_rules two \
		"set skip on ${epair_sync}b" \
		"pass keep state"

	ifconfig ${epair_one}b 198.51.100.254/24 up
	ifconfig ${epair_two}b 198.51.100.253/24 up

	# Create a new state
	env PYTHONPATH=${common_dir} \
		${common_dir}/pft_ping.py \
		--sendif ${epair_one}b \
		--fromaddr 198.51.100.254 \
		--to 198.51.100.1 \
		--recvif ${epair_one}b

	# Now
	jexec one pfctl -ss -vv
	sleep 2

	# Now try to use that state on jail two
	env PYTHONPATH=${common_dir} \
		${common_dir}/pft_ping.py \
		--sendif ${epair_two}b \
		--fromaddr 198.51.100.254 \
		--to 198.51.100.1 \
		--recvif ${epair_two}b

	echo one
	jexec one pfctl -ss -vv
	jexec one pfctl -sr -vv
	echo two
	jexec two pfctl -ss -vv
	jexec two pfctl -sr -vv
}

rtable_cleanup()
{
	pfsynct_cleanup
}

route_to_common_head()
{
	# TODO: Extend setup_router_server_nat64 to create a 2nd router

	pfsync_version=$1
	shift

	pfsynct_init

	epair_sync=$(vnet_mkepair)
	epair_one=$(vnet_mkepair)
	epair_two=$(vnet_mkepair)
	epair_out_one=$(vnet_mkepair)
	epair_out_two=$(vnet_mkepair)

	vnet_mkjail one ${epair_one}a ${epair_sync}a ${epair_out_one}a
	vnet_mkjail two ${epair_two}a ${epair_sync}b ${epair_out_two}a
	pfsynct_mkif one
	pfsynct_mkif two

	# pfsync interface
	jexec one ifconfig ${epair_sync}a 192.0.2.1/24 up
	jexec one ifconfig ${epair_one}a 198.51.100.1/28 up
	jexec one ifconfig ${epair_one}a inet6 2001:db8:4211::1/64 no_dad
	jexec one ifconfig ${epair_one}a name inif
	jexec one ifconfig ${epair_out_one}a 203.0.113.1/24 up
	jexec one ifconfig ${epair_out_one}a inet6 2001:db8:4200::1/64 no_dad
	jexec one ifconfig ${epair_out_one}a name outif
	jexec one sysctl net.inet.ip.forwarding=1
	jexec one sysctl net.inet6.ip6.forwarding=1
	jexec one arp -s 203.0.113.254 00:01:02:00:00:04
	jexec one ndp -s 2001:db8:4200::fe 00:01:02:00:00:06
	jexec one ifconfig pfsync0 \
		syncdev ${epair_sync}a \
		maxupd 1 \
		up

	jexec two ifconfig ${epair_sync}b 192.0.2.2/24 up
	jexec two ifconfig ${epair_two}a 198.51.100.17/28 up
	jexec two ifconfig ${epair_two}a inet6 2001:db8:4212::1/64 no_dad
	jexec two ifconfig ${epair_two}a name inif
	jexec two ifconfig ${epair_out_two}a 203.0.113.1/24 up
	jexec two ifconfig ${epair_out_two}a inet6 2001:db8:4200::2/64 no_dad
	jexec two ifconfig ${epair_out_two}a name outif
	jexec two sysctl net.inet.ip.forwarding=1
	jexec two sysctl net.inet6.ip6.forwarding=1
	jexec two arp -s 203.0.113.254 00:01:02:00:00:04
	jexec two ndp -s 2001:db8:4200::fe 00:01:02:00:00:06
	jexec two ifconfig pfsync0 \
		syncdev ${epair_sync}b \
		maxupd 1 \
		up

	ifconfig ${epair_one}b 198.51.100.2/28 up
	ifconfig ${epair_one}b inet6 2001:db8:4211::2/64 no_dad
	ifconfig ${epair_two}b 198.51.100.18/28 up
	ifconfig ${epair_two}b inet6 2001:db8:4212::2/64 no_dad
	# Target is behind router "one"
	route add -net 203.0.113.0/24 198.51.100.1
	route add -inet6 -net 64:ff9b::/96 2001:db8:4211::1

	ifconfig ${epair_two}b up
	ifconfig ${epair_out_one}b up
	ifconfig ${epair_out_two}b up
}

route_to_common_tail()
{
	atf_check -s exit:0 env PYTHONPATH=${common_dir} \
		${common_dir}/pft_ping.py \
		--sendif ${epair_one}b \
		--fromaddr 198.51.100.254 \
		--to 203.0.113.254 \
		--recvif ${epair_out_one}b

	# Allow time for sync
	sleep 2

	states_one=$(mktemp)
	states_two=$(mktemp)
	jexec one pfctl -qvvss | normalize_pfctl_s > $states_one
	jexec two pfctl -qvvss | normalize_pfctl_s > $states_two
}

atf_test_case "af_to_in_floating" "cleanup"
af_to_in_floating_head()
{
	atf_set descr 'Test syncing of states created by inbound af-to rules with floating states'
	atf_set require.user root
	atf_set require.progs python3 scapy
}

af_to_in_floating_body()
{
	route_to_common_head 1500

	jexec one pfctl -e
	pft_set_rules one \
		"set state-policy floating" \
		"set skip on ${epair_sync}a" \
		"block" \
		"pass inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv } keep state (no-sync)" \
		"pass in on inif to 64:ff9b::/96 af-to inet from (outif) keep state"

	jexec two pfctl -e
	pft_set_rules two \
		"set skip on ${epair_sync}b" \
		"block" \
		"pass inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv } keep state (no-sync)"

	# ptf_ping can't deal with nat64, this test will fail but generate states
	atf_check -s exit:1 env PYTHONPATH=${common_dir} \
		${common_dir}/pft_ping.py \
		--sendif ${epair_one}b \
		--fromaddr 2001:db8:4201::fe \
		--to 64:ff9b::203.0.113.254 \
		--recvif ${epair_out_one}b

	# Allow time for sync
	sleep 2

	states_one=$(mktemp)
	states_two=$(mktemp)
	jexec one pfctl -qvvss | normalize_pfctl_s > $states_one
	jexec two pfctl -qvvss | normalize_pfctl_s > $states_two

	# Sanity check
	grep -qE 'all ipv6-icmp 203.0.113.1(:[0-9]+)? \(2001:db8:4201::fe\) -> 203.0.113.254:8 \(64:ff9b::cb00:71fe(\[[0-9]+\])?\) .* rule 3 ' $states_one ||
		atf_fail "State missing on router one"

	grep -qE 'all ipv6-icmp 203.0.113.1(:[0-9]+)? \(2001:db8:4201::fe\) -> 203.0.113.254:8 \(64:ff9b::cb00:71fe(\[[0-9]+\])?\) ' $states_two ||
		atf_fail "State missing on router two"
}

af_to_in_floating_cleanup()
{
	pfsynct_cleanup
}

atf_test_case "af_to_in_if_bound" "cleanup"
af_to_in_if_bound_head()
{
	atf_set descr 'Test syncing of states created by inbound af-to rules with if-bound states'
	atf_set require.user root
	atf_set require.progs python3 scapy
}

af_to_in_if_bound_body()
{
	route_to_common_head 1500

	jexec one pfctl -e
	pft_set_rules one \
		"set state-policy if-bound" \
		"set skip on ${epair_sync}a" \
		"block" \
		"pass inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv } keep state (no-sync)" \
		"pass in on inif to 64:ff9b::/96 af-to inet from (outif) keep state"

	jexec two pfctl -e
	pft_set_rules two \
		"set skip on ${epair_sync}b" \
		"block" \
		"pass inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv } keep state (no-sync)"

	# ptf_ping can't deal with nat64, this test will fail but generate states
	atf_check -s exit:1 env PYTHONPATH=${common_dir} \
		${common_dir}/pft_ping.py \
		--sendif ${epair_one}b \
		--fromaddr 2001:db8:4201::fe \
		--to 64:ff9b::203.0.113.254 \
		--recvif ${epair_out_one}b

	# Allow time for sync
	sleep 2

	states_one=$(mktemp)
	states_two=$(mktemp)
	jexec one pfctl -qvvss | normalize_pfctl_s > $states_one
	jexec two pfctl -qvvss | normalize_pfctl_s > $states_two

	# 5BSD: an af-to state floats even with if-bound (pf.c); pfctl has
	# no "origif".
	# Sanity check
	grep -qE 'all ipv6-icmp 203.0.113.1(:[0-9]+)? \(2001:db8:4201::fe\) -> 203.0.113.254:8 \(64:ff9b::cb00:71fe(\[[0-9]+\])?\) .* rule 3 ' $states_one ||
		atf_fail "State missing on router one"

	grep -qE 'all ipv6-icmp 203.0.113.1(:[0-9]+)? \(2001:db8:4201::fe\) -> 203.0.113.254:8 \(64:ff9b::cb00:71fe(\[[0-9]+\])?\) ' $states_two ||
		atf_fail "State missing on router two"
}

af_to_in_if_bound_cleanup()
{
	pfsynct_cleanup
}

atf_test_case "flush_by_intf" "cleanup"
flush_by_intf_head()
{
	atf_set descr 'Test flushing states by interface'
	atf_set require.user root
}

flush_by_intf_body()
{
	pfsynct_init

	epair_sync=$(vnet_mkepair)
	epair_one=$(vnet_mkepair)
	epair_two=$(vnet_mkepair)

	vnet_mkjail one ${epair_one}a ${epair_sync}a
	vnet_mkjail two ${epair_two}a ${epair_sync}b
	pfsynct_mkif one
	pfsynct_mkif two

	# pfsync interface
	jexec one ifconfig ${epair_sync}a 192.0.2.1/24 up
	jexec one ifconfig ${epair_one}a name epair_foo
	jexec one ifconfig epair_foo 198.51.100.1/24 up
	jexec one ifconfig pfsync0 \
		syncdev ${epair_sync}a \
		maxupd 1 \
		up
	jexec two ifconfig ${epair_sync}b 192.0.2.2/24 up
	jexec two ifconfig ${epair_two}a name epair_foo
	jexec two ifconfig epair_foo 198.51.100.2/24 up
	jexec two ifconfig pfsync0 \
		syncdev ${epair_sync}b \
		maxupd 1 \
		up

	jexec one pfctl -e
	pft_set_rules one \
		"set state-policy if-bound" \
		"set skip on ${epair_sync}a" \
		"pass out keep state"
	jexec two pfctl -e
	pft_set_rules two \
		"set state-policy if-bound" \
		"set skip on ${epair_sync}b" \
		"pass out keep state"

	ifconfig ${epair_one}b 198.51.100.254/24 up

	jexec one ping -c 1 -S 198.51.100.1 198.51.100.254

	# Give pfsync time to do its thing
	sleep 2

	if ! jexec two pfctl -s states | grep icmp | grep 198.51.100.1 | \
	    grep 198.51.100.254 ; then
		atf_fail "state not found on synced host"
	fi

	# Now flush states in one, with an interface specified
	# (Note the interface must exist on both hosts for the bug to manifest)
	jexec one pfctl -i lo0 -Fs

	sleep 2

	if ! jexec two pfctl -s states | grep icmp | grep 198.51.100.1 | \
	    grep 198.51.100.254 ; then
		atf_fail "state was removed on synced host!"
	fi

	# Now flush on the interface the state is actually on, this should get passed to
	# the peer.
	jexec one pfctl -i epair_foo -Fs

	sleep 2

	if jexec two pfctl -s states | grep icmp | grep 198.51.100.1 | \
	    grep 198.51.100.254 ; then
		atf_fail "state was not removed on synced host!"
	fi
}

flush_by_intf_cleanup()
{
	pfsynct_cleanup
}

atf_test_case "lifecycle_departure" "cleanup"
lifecycle_departure_head()
{
	atf_set descr 'Drain pfsync hooks and timers across detach, VNET move, and destroy'
	atf_set require.user root
	atf_set timeout 300
}

lifecycle_departure_body()
{
	pft_init
	vnet_mkjail pfsync_lifecycle

	i=0
	while [ $i -lt 16 ]; do
		ep=$(vnet_mkepair)
		[ -n "$ep" ] || atf_fail 'could not create epair'
		ifconfig ${ep}b vnet pfsync_lifecycle ||
		    atf_fail "moving ${ep}b into jail"
		jexec pfsync_lifecycle ifconfig ${ep}b 192.0.2.1/24 up ||
		    atf_fail "configuring ${ep}b"
		jexec pfsync_lifecycle ifconfig pfsync0 create ||
		    atf_fail 'creating pfsync0'
		jexec pfsync_lifecycle ifconfig pfsync0 syncdev ${ep}b up ||
		    atf_fail "starting pfsync0 on ${ep}b"
		jexec pfsync_lifecycle ifconfig pfsync0 down ||
		    atf_fail 'stopping pfsync0'
		jexec pfsync_lifecycle ifconfig pfsync0 up ||
		    atf_fail 'restarting pfsync0'

		if [ $((i % 2)) -eq 0 ]; then
			ifconfig ${ep}a destroy ||
			    atf_fail "detaching ${ep}a"
		else
			ifconfig ${ep}b -vnet pfsync_lifecycle ||
			    atf_fail "reclaiming ${ep}b from jail"
			ifconfig ${ep}a destroy ||
			    atf_fail "destroying ${ep}a after VNET move"
		fi
		unlist_interface ${ep}a
		unlist_interface ${ep}b
		jexec pfsync_lifecycle ifconfig pfsync0 destroy ||
		    atf_fail 'destroying pfsync0 after departure'
		i=$((i + 1))
	done
}

lifecycle_departure_cleanup()
{
	pft_cleanup
}

atf_test_case "ipv6_syncpeer" "cleanup"
ipv6_syncpeer_head()
{
	atf_set descr 'IPv6 unicast sync peer: configuration, MTU and bulk update (5BSD extension)'
	atf_set require.user root
}

ipv6_syncpeer_body()
{
	pfsynct_init

	epair_sync=$(vnet_mkepair)
	epair_one=$(vnet_mkepair)

	vnet_mkjail one ${epair_one}a ${epair_sync}a
	vnet_mkjail two ${epair_sync}b
	pfsynct_mkif one
	pfsynct_mkif two

	# The sync link has IPv6 addresses only.
	jexec one ifconfig ${epair_sync}a inet6 fd2c::1/64 no_dad up
	jexec two ifconfig ${epair_sync}b inet6 fd2c::2/64 no_dad up
	jexec one ifconfig ${epair_one}a inet6 fd2b::1/64 no_dad up
	ifconfig ${epair_one}b inet6 fd2b::f0/64 no_dad up
	ifconfig ${epair_one}b inet6 fd2b::f1/64 alias no_dad

	jexec one ifconfig pfsync0 \
		syncdev ${epair_sync}a \
		syncpeer fd2c::2 \
		maxupd 1
	atf_check -o match:"syncpeer: fd2c::2 " jexec one ifconfig pfsync0

	# The IPv6 header is 20 bytes longer than the IPv4 one pfsync sizes
	# its packets for: the pfsync MTU stays 20 bytes below the syncdev's.
	atf_check -s not-exit:0 -e ignore jexec one ifconfig pfsync0 mtu 1500
	atf_check jexec one ifconfig pfsync0 up
	atf_check -o match:"mtu 1480" jexec one ifconfig pfsync0

	# The peer can only change while pfsync0 is down.
	atf_check -s not-exit:0 -e match:"busy" \
	    jexec one ifconfig pfsync0 syncpeer fd2c::3

	# No IPv4 on the sync link; pfsync itself is not synced.
	jexec one pfctl -e
	pft_set_rules one \
		"block on ${epair_sync}a inet" \
		"pass quick on ${epair_sync}a inet6 proto pfsync keep state (no-sync)" \
		"pass out keep state"
	jexec two pfctl -e
	pft_set_rules two \
		"block on ${epair_sync}b inet" \
		"pass quick on ${epair_sync}b inet6 proto pfsync keep state (no-sync)" \
		"pass out keep state"

	# A state that exists before two starts reaches it by bulk update.
	jexec one ping6 -c 1 -S fd2b::1 fd2b::f0
	sleep 1

	jexec two ifconfig pfsync0 \
		syncdev ${epair_sync}b \
		syncpeer fd2c::1 \
		maxupd 1 \
		up
	sleep 2

	if ! jexec two pfctl -s states | grep icmp | grep fd2b::1 | \
	    grep fd2b::f0 ; then
		jexec two pfctl -s states
		atf_fail "bulk-updated state not found on synced host"
	fi

	# A new state reaches it as an insert.
	jexec one ping6 -c 1 -S fd2b::1 fd2b::f1
	sleep 2

	if ! jexec two pfctl -s states | grep icmp | grep fd2b::1 | \
	    grep fd2b::f1 ; then
		jexec two pfctl -s states
		atf_fail "inserted state not found on synced host"
	fi

	# Back to IPv4: an IPv4 peer replaces the IPv6 one, and -syncpeer
	# returns to the default group (not shown).
	atf_check jexec one ifconfig pfsync0 down syncpeer 192.0.2.2 up
	atf_check -o match:"syncpeer: 192.0.2.2 " -o not-match:"fd2c::" \
	    jexec one ifconfig pfsync0
	atf_check jexec one ifconfig pfsync0 down -syncpeer
	atf_check -o not-match:"syncpeer" jexec one ifconfig pfsync0
}

ipv6_syncpeer_cleanup()
{
	pfsynct_cleanup
}

pfsynct_demotion()
{
	jexec $1 sysctl -n net.inet.carp.demotion
}

# pfsynct_wait_demotion jail value seconds
pfsynct_wait_demotion()
{
	local jail want secs

	jail=$1
	want=$2
	secs=$3
	while [ "$(pfsynct_demotion ${jail})" != "${want}" ]; do
		if [ ${secs} -le 0 ]; then
			atf_fail "net.inet.carp.demotion in ${jail} is" \
			    "$(pfsynct_demotion ${jail}), expected ${want}"
		fi
		sleep 1
		secs=$((secs - 1))
	done
}

atf_test_case "carp_demotion" "cleanup"
carp_demotion_head()
{
	atf_set descr 'pfsync demotes carp until it is synchronised and undoes it on failure, down and destroy'
	atf_set require.user root
	atf_set timeout 300
}

carp_demotion_body()
{
	if ! kldstat -q -m carp
	then
		atf_skip "This test requires carp"
	fi
	pfsynct_init

	epair_sync=$(vnet_mkepair)

	vnet_mkjail one ${epair_sync}a
	vnet_mkjail two ${epair_sync}b
	pfsynct_mkif one

	jexec one ifconfig ${epair_sync}a 192.0.2.1/24 up
	jexec two ifconfig ${epair_sync}b 192.0.2.2/24 up

	# pfsync only processes input while pf is enabled.
	jexec one pfctl -e
	pft_set_rules one \
		"set skip on ${epair_sync}a" \
		"pass"
	jexec two pfctl -e
	pft_set_rules two \
		"set skip on ${epair_sync}b" \
		"pass"

	atf_check -o inline:"0\n" jexec one sysctl -n net.inet.carp.demotion
	atf_check -o inline:"240\n" \
	    jexec one sysctl -n net.pfsync.carp_demotion_factor

	# Nobody answers the bulk update request: pfsync0 is demoted from
	# "up" until it gives up (12 requests, 2 seconds apart).
	jexec one ifconfig pfsync0 syncdev ${epair_sync}a up
	atf_check -o inline:"240\n" jexec one sysctl -n net.inet.carp.demotion

	# A new factor applies at once and leaves no residue.
	atf_check -o ignore jexec one sysctl net.pfsync.carp_demotion_factor=100
	atf_check -o inline:"100\n" jexec one sysctl -n net.inet.carp.demotion
	atf_check -o ignore jexec one sysctl net.pfsync.carp_demotion_factor=240
	atf_check -o inline:"240\n" jexec one sysctl -n net.inet.carp.demotion
	atf_check -s not-exit:0 -o ignore -e ignore \
	    jexec one sysctl net.pfsync.carp_demotion_factor=-1

	# The failed bulk update ends the demotion (12 requests 2 s apart,
	# after up to 30 s waiting for the link; slow on an emulated VM).
	pfsynct_wait_demotion one 0 90

	# Destroying a demoted pfsync0 removes its demotion.
	jexec one ifconfig pfsync0 down
	jexec one ifconfig pfsync0 up
	atf_check -o inline:"240\n" jexec one sysctl -n net.inet.carp.demotion
	jexec one ifconfig pfsync0 destroy
	atf_check -o inline:"0\n" jexec one sysctl -n net.inet.carp.demotion

	# So does bringing it down.
	pfsynct_mkif one
	jexec one ifconfig pfsync0 syncdev ${epair_sync}a up
	atf_check -o inline:"240\n" jexec one sysctl -n net.inet.carp.demotion
	jexec one ifconfig pfsync0 down
	atf_check -o inline:"0\n" jexec one sysctl -n net.inet.carp.demotion

	# A peer answers: the bulk update completes and the demotion ends
	# well before the request retries would run out.  A peer with no
	# states sends only a bulk end, which OpenBSD ignores until the
	# start, so give "two" a state to send.
	jexec two ifconfig lo0 127.0.0.1/8 up
	pft_set_rules two \
		"set skip on ${epair_sync}b" \
		"set timeout icmp.first 600" \
		"pass"
	atf_check -o ignore jexec two ping -c 1 127.0.0.1
	pfsynct_mkif two
	jexec two ifconfig pfsync0 syncdev ${epair_sync}b up
	jexec one ifconfig pfsync0 up
	pfsynct_wait_demotion one 0 10

	# The sync link going down demotes; coming back up undoes it.  An
	# epair's link stays up when it is configured down (OpenBSD's pair
	# reports it down), so the link is a tap's, up while its device is
	# open.  Nobody answers on the tap: wait out the bulk update first.
	jexec one ifconfig pfsync0 destroy
	tap=$(ifconfig tap create)
	list_interface ${tap}
	ifconfig ${tap} vnet one
	jexec one ifconfig ${tap} 192.0.2.1/24 up
	carp_demotion_tap_open ${tap}
	pfsynct_mkif one
	jexec one ifconfig pfsync0 syncdev ${tap} up
	pfsynct_wait_demotion one 0 90
	carp_demotion_tap_close
	pfsynct_wait_demotion one 240 5
	carp_demotion_tap_open ${tap}
	pfsynct_wait_demotion one 0 5

	# Destroy with the link down leaves nothing behind either.
	carp_demotion_tap_close
	pfsynct_wait_demotion one 240 5
	jexec one ifconfig pfsync0 destroy
	atf_check -o inline:"0\n" jexec one sysctl -n net.inet.carp.demotion
}

# A tap's link is up while a process holds its device open.
carp_demotion_tap_open()
{
	daemon -p carp_demotion_tap.pid sh -c "exec 3<>/dev/$1; sleep 600"
	sleep 1
}

carp_demotion_tap_close()
{
	kill $(cat carp_demotion_tap.pid)
	rm -f carp_demotion_tap.pid
}

carp_demotion_cleanup()
{
	[ -f carp_demotion_tap.pid ] && kill $(cat carp_demotion_tap.pid)
	pfsynct_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "basic"
	atf_add_test_case "basic_defer"
	atf_add_test_case "defer"
	atf_add_test_case "bulk"
	atf_add_test_case "pbr"
	atf_add_test_case "pfsync_pbr"
	atf_add_test_case "ipsec"
	atf_add_test_case "timeout"
	atf_add_test_case "basic_ipv6_unicast"
	atf_add_test_case "basic_ipv6"
	atf_add_test_case "rtable"
	atf_add_test_case "af_to_in_floating"
	atf_add_test_case "af_to_in_if_bound"
	atf_add_test_case "flush_by_intf"
	atf_add_test_case "lifecycle_departure"
	atf_add_test_case "ipv6_syncpeer"
	atf_add_test_case "carp_demotion"
}
