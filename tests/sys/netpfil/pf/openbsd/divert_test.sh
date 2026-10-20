#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 The 5BSD Project
#
# OpenBSD PF transparent proxying: divert-to delivers a connection for a
# foreign destination to a local socket, which still sees the original
# destination (getsockname(2) for TCP, IP_RECVDSTADDR/IP_RECVDSTPORT and
# IPV6_PKTINFO/IPV6_RECVDSTPORT for UDP).  The client runs in a vnet jail
# behind the host, which runs pf and the proxy.

. $(atf_get_srcdir)/../../../common/vnet.subr

PROXY=$(atf_get_srcdir)/tproxy.py

setup()
{
	vnet_init
	kldstat -q -m pf || atf_skip "pf is not loaded"
	which python3 >/dev/null 2>&1 || atf_skip "python3 is required"

	epair=$(vnet_mkepair)
	ifconfig ${epair}a inet 192.0.2.1/30 up
	ifconfig ${epair}a inet6 2001:db8:42::1/64 no_dad up
	vnet_mkjail tpc ${epair}b
	jexec tpc ifconfig lo0 inet 127.0.0.1/8 up
	jexec tpc ifconfig ${epair}b inet 192.0.2.2/30 up
	jexec tpc ifconfig ${epair}b inet6 2001:db8:42::2/64 no_dad up
	jexec tpc route -q add -inet default 192.0.2.1
	jexec tpc route -q add -inet6 default 2001:db8:42::1
	# The proxied destinations do not exist anywhere.
	route -q add -inet 198.51.100.0/24 -blackhole 127.0.0.1 >/dev/null 2>&1
	route -q add -inet6 2001:db8:dead::/48 -blackhole ::1 >/dev/null 2>&1
	sysctl -q net.inet.ip.forwarding=1 net.inet6.ip6.forwarding=1 >/dev/null

	printf '%s\n' \
	    "pass" \
	    "pass in on ${epair}a inet proto tcp to port 80 divert-to 127.0.0.1 port 8080" \
	    "pass in on ${epair}a inet6 proto tcp to port 80 divert-to ::1 port 8080" \
	    "pass in on ${epair}a inet proto udp to port 53 divert-to 127.0.0.1 port 5353" \
	    "pass in on ${epair}a inet6 proto udp to port 53 divert-to ::1 port 5353" |
	    atf_check -s exit:0 -o ignore -e ignore pfctl -f -
	# Restored by the cleanup: later cases expect the host pf as it was.
	pfctl -si 2>/dev/null | grep -q "^Status: Enabled" || touch pf.was_disabled
	pfctl -e >/dev/null 2>&1 || true
}

# start_proxy <tcp|udp> <addr> <port> <count>
start_proxy()
{
	python3 ${PROXY} "$@" > proxy.out 2> proxy.err &
	echo $! > proxy.pid
	i=0
	while ! grep -q READY proxy.out 2>/dev/null; do
		i=$((i + 1))
		[ $i -lt 50 ] || atf_fail "proxy did not start: $(cat proxy.err)"
		sleep 0.1
	done
}

stop_proxy()
{
	[ -f proxy.pid ] && kill $(cat proxy.pid) >/dev/null 2>&1
	rm -f proxy.pid
}

cleanup()
{
	stop_proxy
	pfctl -Fa >/dev/null 2>&1
	[ -f pf.was_disabled ] && pfctl -q -d >/dev/null 2>&1
	route -q delete -inet 198.51.100.0/24 >/dev/null 2>&1
	route -q delete -inet6 2001:db8:dead::/48 >/dev/null 2>&1
	vnet_cleanup
}

atf_test_case "tcp_v4" "cleanup"
tcp_v4_head()
{
	atf_set descr 'HTTP through a divert-to proxy sees the IPv4 destination'
	atf_set require.user root
}
tcp_v4_body()
{
	setup
	start_proxy tcp 127.0.0.1 8080 2
	atf_check -s exit:0 -o match:'origdst=198.51.100.80 port=80 peer=192.0.2.2' \
	    jexec tpc fetch -q -T 5 -o - http://198.51.100.80/
	atf_check -s exit:0 -o match:'origdst=198.51.100.7 port=80' \
	    jexec tpc fetch -q -T 5 -o - http://198.51.100.7:80/index.html
	# The state shows the original destination and the divert.
	atf_check -s exit:0 -o match:'198.51.100.80:80' pfctl -ss
}
tcp_v4_cleanup()
{
	cleanup
}

atf_test_case "tcp_v6" "cleanup"
tcp_v6_head()
{
	atf_set descr 'HTTP through a divert-to proxy sees the IPv6 destination'
	atf_set require.user root
}
tcp_v6_body()
{
	setup
	start_proxy tcp ::1 8080 1
	atf_check -s exit:0 \
	    -o match:'origdst=2001:db8:dead::80 port=80 peer=2001:db8:42::2' \
	    jexec tpc fetch -q -T 5 -o - 'http://[2001:db8:dead::80]/'
}
tcp_v6_cleanup()
{
	cleanup
}

atf_test_case "udp_v4" "cleanup"
udp_v4_head()
{
	atf_set descr 'divert-to UDP keeps the original destination address and port'
	atf_set require.user root
}
udp_v4_body()
{
	setup
	start_proxy udp 127.0.0.1 5353 1
	atf_check -s exit:0 -o match:'origdst=198.51.100.53 port=53' \
	    jexec tpc sh -c 'echo q | nc -u -w 2 198.51.100.53 53'
}
udp_v4_cleanup()
{
	cleanup
}

atf_test_case "udp_v6" "cleanup"
udp_v6_head()
{
	atf_set descr 'divert-to UDP keeps the original IPv6 destination and port'
	atf_set require.user root
}
udp_v6_body()
{
	setup
	start_proxy udp ::1 5353 1
	atf_check -s exit:0 -o match:'origdst=2001:db8:dead::53 port=53' \
	    jexec tpc sh -c 'echo q | nc -u -w 2 2001:db8:dead::53 53'
}
udp_v6_cleanup()
{
	cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "tcp_v4"
	atf_add_test_case "tcp_v6"
	atf_add_test_case "udp_v4"
	atf_add_test_case "udp_v6"
}
