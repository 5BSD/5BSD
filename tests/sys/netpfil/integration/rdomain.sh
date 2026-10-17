#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 The 5BSD Project
#
# Routing domains (OpenBSD rdomain(4), built on FreeBSD FIBs) inside VNET
# jails and with pf: a VNET jail's domain N is not the host's domain N;
# pf "on rdomain N", "rtable N" and per-domain state kills; SO_RTABLE
# (SO_SETFIB) and setfib(1) privilege as described in UPDATING 20261012.
# tests/sys/net/rdomain_test.sh covers the domains themselves.

. $(atf_get_srcdir)/integration.subr

HELPER=$(atf_get_srcdir)/sockhelper

rd_jail()
{
	vnet_mkjail $1 $2
	jexec $1 ifconfig lo0 inet 127.0.0.1/8 up
}

atf_test_case "vnet_isolation" "cleanup"
vnet_isolation_head()
{
	atf_set descr 'Routing domain N of a VNET jail is not the host domain N, nor another jail'"'"'s'
	atf_set require.user root
}
vnet_isolation_body()
{
	pft_init
	if ifconfig lo13 >/dev/null 2>&1 || route -T 13 -n show >/dev/null 2>&1
	then
		atf_skip "the host already has routing table 13"
	fi

	rd_jail a
	rd_jail b
	for j in a b; do
		atf_check -s exit:0 -o ignore jexec $j ifconfig vether0 create rdomain 13
		atf_check -s exit:0 jexec $j ifconfig vether0 inet 192.0.2.1/24 up
		atf_check -s exit:0 -o match:'^lo13: .* rdomain 13 ' \
		    jexec $j ifconfig lo13
		atf_check -s exit:0 -o match:'1 packets received' \
		    jexec $j ping -n -c 1 -t 5 -V 13 192.0.2.1
	done
	# A route in b's domain 13 is not in a's domain 13.
	atf_check -s exit:0 -o ignore \
	    jexec b route -T 13 add 203.0.113.0/24 192.0.2.254
	atf_check -s exit:0 -o match:'203\.0\.113' jexec b route -T 13 -n show
	atf_check -s exit:0 -o not-match:'203\.0\.113' jexec a route -T 13 -n show

	# The host has neither the domain nor its loopback.
	atf_check -s not-exit:0 -e ignore ifconfig lo13
	atf_check -s not-exit:0 -e match:'routing table 13' route -T 13 -n show
	atf_check -s not-exit:0 -e ignore setfib 13 true

	# Removing jail a leaves b's domain alone.
	atf_check -s exit:0 jail -r a
	sed -i '' '/^a$/d' created_jails.lst
	atf_check -s exit:0 -o match:'1 packets received' \
	    jexec b ping -n -c 1 -t 5 -V 13 192.0.2.1
	atf_check -s not-exit:0 -e ignore ifconfig lo13
}
vnet_isolation_cleanup()
{
	integ_cleanup
}

atf_test_case "pf_on_rdomain" "cleanup"
pf_on_rdomain_head()
{
	atf_set descr 'pf "on rdomain N" in a VNET jail matches only that domain'
	atf_set require.user root
}
pf_on_rdomain_body()
{
	pft_init
	rd_jail fw
	for d in 1 2; do
		atf_check -s exit:0 jexec fw ifconfig lo$d rdomain $d
		atf_check -s exit:0 jexec fw ifconfig lo$d inet 127.0.0.1/8 up
	done
	atf_check -s exit:0 -e ignore jexec fw pfctl -e

	pft_set_rules fw "pass all" \
	    "block in quick on rdomain 1 inet proto icmp"
	atf_check -s exit:0 -o match:'block drop in quick on rdomain 1 inet proto icmp' \
	    jexec fw pfctl -sr
	atf_check -s ignore -o ignore -e ignore \
	    jexec fw ping -n -c 1 -t 2 -V 1 127.0.0.1
	atf_check -s exit:0 -o match:'1 packets received' \
	    jexec fw ping -n -c 1 -t 5 -V 2 127.0.0.1
	atf_check -s exit:0 -o match:'1 packets received' \
	    jexec fw ping -n -c 1 -t 5 127.0.0.1

	# The rule counted only domain 1's packets.
	atf_check -s exit:0 -o match:'Packets: [1-9]' \
	    sh -c "jexec fw pfctl -vsr | grep -A2 'on rdomain 1'"
	# The host's pf has no such rule.
	atf_check -s exit:0 -o not-match:'rdomain 1' pfctl -sr
}
pf_on_rdomain_cleanup()
{
	integ_cleanup
}

atf_test_case "state_kill_rdomain" "cleanup"
state_kill_rdomain_head()
{
	atf_set descr 'States of equal addresses in two domains are separate; pfctl -V kills one domain'
	atf_set require.user root
}
state_kill_rdomain_body()
{
	pft_init
	rd_jail fw
	for d in 1 2; do
		atf_check -s exit:0 jexec fw ifconfig lo$d rdomain $d
		atf_check -s exit:0 jexec fw ifconfig lo$d inet 127.0.0.1/8 up
	done
	atf_check -s exit:0 -e ignore jexec fw pfctl -e
	pft_set_rules fw "pass all"

	# The same addresses and ports in both domains: two separate states.
	for d in 1 2; do
		echo x | jexec fw route -T $d exec nc -u -w 1 -p 7100 127.0.0.1 7101
	done
	atf_check -s exit:0 -o match:'^2$' \
	    sh -c "jexec fw pfctl -ss | grep -c '127.0.0.1:7100 -> 127.0.0.1:7101'"

	# Killing in domain 1 leaves domain 2's state.
	atf_check -s exit:0 -e match:'killed [1-9][0-9]* states' \
	    jexec fw pfctl -V 1 -k 127.0.0.1
	atf_check -s exit:0 -o match:'^1$' \
	    sh -c "jexec fw pfctl -ss | grep -c '127.0.0.1:7100 -> 127.0.0.1:7101'"
	atf_check -s exit:0 -e match:'killed [1-9][0-9]* states' \
	    jexec fw pfctl -V 2 -k 127.0.0.1
	atf_check -s exit:0 -o match:'^0$' \
	    sh -c "jexec fw pfctl -ss | grep -c '127.0.0.1:7100 -> 127.0.0.1:7101'"
}
state_kill_rdomain_cleanup()
{
	integ_cleanup
}

atf_test_case "rtable_cross_domain" "cleanup"
rtable_cross_domain_head()
{
	atf_set descr 'pf "rtable N" on an inbound rule delivers into routing domain N'
	atf_set require.user root
}
rtable_cross_domain_body()
{
	pft_init
	epair=$(vnet_mkepair)
	rd_jail cli ${epair}a
	rd_jail fw ${epair}b
	jexec cli ifconfig ${epair}a 192.0.2.2/24 up
	jexec cli route -q add 198.51.100.0/24 192.0.2.1
	jexec fw ifconfig ${epair}b 192.0.2.1/24 up
	# 198.51.100.1 exists only in fw's routing domain 2.
	atf_check -s exit:0 -o ignore jexec fw ifconfig vether0 create rdomain 2
	atf_check -s exit:0 jexec fw ifconfig vether0 inet 198.51.100.1/24 up
	atf_check -s exit:0 -e ignore jexec fw pfctl -e

	: > out
	jexec fw route -T 2 exec nc -u -l 198.51.100.1 7201 > out 2>/dev/null &
	sleep 1

	# Without rtable the packet arrives in domain 0, where the address
	# is not local: nothing is received.
	pft_set_rules fw "pass all"
	echo dom0 | jexec cli nc -u -w 1 198.51.100.1 7201
	sleep 1
	atf_check -s exit:0 -o empty cat out

	# With rtable 2 it is delivered in domain 2.
	pft_set_rules fw "pass all" \
	    "pass in quick on ${epair}b inet proto udp to 198.51.100.1 port 7201 rtable 2"
	atf_check -s exit:0 -o match:'rtable 2' jexec fw pfctl -sr
	echo dom2 | jexec cli nc -u -w 1 198.51.100.1 7201
	sleep 1
	atf_check -s exit:0 -o inline:'dom2\n' cat out
}
rtable_cross_domain_cleanup()
{
	integ_cleanup
}

atf_test_case "rtable_privilege" "cleanup"
rtable_privilege_head()
{
	atf_set descr 'SO_RTABLE and setfib: tables of the own domain are free, another domain needs root'
	atf_set require.user root
	atf_set require.progs su
}
rtable_privilege_body()
{
	pft_init
	rd_jail fw
	# Table 4 belongs to domain 0; table 6 is routing domain 6.
	atf_check -s exit:0 -o ignore jexec fw route -T 4 add 198.51.100.0/24 127.0.0.1
	atf_check -s exit:0 jexec fw ifconfig lo6 rdomain 6

	atf_check -s exit:0 -o inline:'setsockopt=ok rtable=4\n' \
	    jexec -U nobody fw ${HELPER} rtable 4
	atf_check -s exit:0 -o inline:'setsockopt=EPERM rtable=0\n' \
	    jexec -U nobody fw ${HELPER} rtable 6
	atf_check -s exit:0 -o inline:'setsockopt=ok rtable=6\n' \
	    jexec fw ${HELPER} rtable 6

	# setfib(1) follows the same rule.
	atf_check -s exit:0 jexec -U nobody fw setfib 4 true
	atf_check -s not-exit:0 -e match:'Operation not permitted' \
	    jexec -U nobody fw setfib 6 true
	atf_check -s exit:0 jexec fw setfib 6 true
	atf_check -s exit:0 -o inline:'6\n' \
	    jexec fw route -T 6 exec sysctl -n net.my_fibnum
}
rtable_privilege_cleanup()
{
	integ_cleanup
}

atf_test_case "fib_vmove" "cleanup"
fib_vmove_head()
{
	atf_set descr 'An interface returning from a VNET with more FIBs to one with fewer gets FIB 0 (no FIB lookup past the tables)'
	atf_set require.user root
}

fib_vmove_body()
{
	pft_init
	[ "$(sysctl -n net.fibs)" -eq 1 ] ||
	    atf_skip "the host vnet has more than one FIB"
	e=$(vnet_mkepair)
	vnet_mkjail many ${e}b
	jexec many sysctl net.fibs=2 >/dev/null 2>&1 ||
	    atf_skip "net.fibs cannot be raised in a vnet jail"
	atf_check -s exit:0 jexec many ifconfig ${e}b fib 1
	atf_check -s exit:0 -o match:"fib: 1" jexec many ifconfig ${e}b

	# The jail goes away; its interfaces return to the host vnet.
	jail -r many
	sed -i '' '/^many$/d' created_jails.lst 2>/dev/null
	atf_check -s exit:0 -o not-match:"fib:" ifconfig ${e}b

	# Traffic received on it is looked up in FIB 0, without a panic.
	vnet_mkjail peer ${e}a
	jexec peer ifconfig ${e}a 192.0.2.1/24 up
	ifconfig ${e}b 192.0.2.2/24 up
	atf_check -s exit:0 -o ignore ping -c 2 -t 4 192.0.2.1
	# An ICMP error reflected on the moved interface (unreachable port).
	atf_check -s ignore -o ignore -e ignore \
	    jexec peer nc -u -z -w 2 192.0.2.2 9
}

fib_vmove_cleanup()
{
	pft_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "vnet_isolation"
	atf_add_test_case "pf_on_rdomain"
	atf_add_test_case "state_kill_rdomain"
	atf_add_test_case "rtable_cross_domain"
	atf_add_test_case "rtable_privilege"
	atf_add_test_case "fib_vmove"
}
