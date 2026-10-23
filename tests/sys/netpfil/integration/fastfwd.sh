#
# SPDX-License-Identifier: BSD-2-Clause
#
# pf on FreeBSD's IPv6 fast forwarding path.  With net.inet6.ip6.redirect=0
# a forwarding host hands packets to ip6_tryforward(), which runs the pfil
# hooks itself (inbound, then outbound with PFIL_FWD) instead of
# ip6_input() and ip6_forward().  The default (redirects on) never takes it.
#

. $(atf_get_srcdir)/integration.subr

# ff_topology: client --(a)-- rtr --(b)-- srv, rtr forwarding on the fast
# path.  2001:db8:1::/64 on a, 2001:db8:2::/64 on b.
ff_topology()
{
	pft_init
	epa=$(vnet_mkepair)
	epb=$(vnet_mkepair)
	vnet_mkjail cl ${epa}a
	vnet_mkjail rtr ${epa}b ${epb}a
	vnet_mkjail srv ${epb}b
	jexec cl ifconfig ${epa}a inet6 2001:db8:1::2/64 up no_dad
	jexec rtr ifconfig ${epa}b inet6 2001:db8:1::1/64 up no_dad
	jexec rtr ifconfig ${epb}a inet6 2001:db8:2::1/64 up no_dad
	jexec srv ifconfig ${epb}b inet6 2001:db8:2::2/64 up no_dad
	jexec cl route -q -6 add default 2001:db8:1::1
	jexec srv route -q -6 add default 2001:db8:2::1
	jexec rtr sysctl -q net.inet6.ip6.forwarding=1
	jexec rtr sysctl -q net.inet6.ip6.redirect=0
	jexec rtr pfctl -e > /dev/null 2>&1
	jexec srv ifconfig lo0 inet 127.0.0.1/8 up
}

# ff_serve jail port: a TCP server answering "ff" once per connection.
ff_serve()
{
	jexec $1 sh -c "while :; do echo ff | nc -6 -N -l $2; done" \
	    > /dev/null 2>&1 &
	n=0
	until jexec $1 sockstat -6 -l -p $2 | grep -q nc; do
		n=$((n + 1))
		[ ${n} -le 50 ] || atf_fail "server on port $2 did not start"
		sleep 0.2
	done
}

# ff_forwarded: IPv6 packets the router forwarded so far.
ff_forwarded()
{
	jexec rtr netstat -s -p ip6 --libxo json |
	    sed -nE 's/.*"forwarded-packets": *([0-9]+).*/\1/p'
}

atf_test_case "pass_block" "cleanup"
pass_block_head()
{
	atf_set descr 'Rules and states on the IPv6 fast forwarding path'
	atf_set require.user root
}

pass_block_body()
{
	ff_topology
	pft_set_rules rtr \
	    "block in quick inet6 proto tcp to port 8889" \
	    "pass"
	ff_serve srv 8888
	ff_serve srv 8889
	before=$(ff_forwarded)

	atf_check -s exit:0 -o ignore jexec cl ping -6 -c 1 2001:db8:2::2
	atf_check -s exit:0 -o inline:"ff\n" \
	    jexec cl nc -6 -N -w 5 2001:db8:2::2 8888
	atf_check -s not-exit:0 -o empty \
	    jexec cl nc -6 -N -w 2 2001:db8:2::2 8889

	# The packets were forwarded, with a state for the connection.
	after=$(ff_forwarded)
	[ "${after}" -gt "${before}" ] ||
	    atf_fail "nothing forwarded (${before} -> ${after})"
	atf_check -s exit:0 -o match:"2001:db8:1::2\[[0-9]+\] -> 2001:db8:2::2\[8888\]" \
	    jexec rtr pfctl -ss
	atf_check -s exit:0 -o match:"Packets: [1-9]" \
	    sh -c "jexec rtr pfctl -vsr | grep -A2 'port = 8889'"
}

pass_block_cleanup()
{
	pft_cleanup
}

atf_test_case "nat66" "cleanup"
nat66_head()
{
	atf_set descr 'nat-to on the IPv6 fast forwarding path'
	atf_set require.user root
}

nat66_body()
{
	ff_topology
	# The last matching rule wins: the translation comes after "pass".
	pft_set_rules rtr \
	    "pass" \
	    "pass out on ${epb}a inet6 nat-to 2001:db8:2::1"
	# The server only talks to the router's address: the client gets
	# through only translated.
	jexec srv pfctl -e > /dev/null 2>&1
	pft_set_rules srv \
	    "block in inet6 proto tcp" \
	    "pass in inet6 proto tcp from 2001:db8:2::1" \
	    "pass out"
	ff_serve srv 8888

	atf_check -s exit:0 -o inline:"ff\n" \
	    jexec cl nc -6 -N -w 5 2001:db8:2::2 8888
	atf_check -s exit:0 -o match:"2001:db8:2::1\[[0-9]+\] \(2001:db8:1::2\[[0-9]+\]\) -> 2001:db8:2::2\[8888\]" \
	    jexec rtr pfctl -ss
}

nat66_cleanup()
{
	pft_cleanup
}

atf_test_case "rdr66" "cleanup"
rdr66_head()
{
	atf_set descr 'rdr-to on the IPv6 fast forwarding path'
	atf_set require.user root
}

rdr66_body()
{
	ff_topology
	# 2001:db8:3::80 does not exist; the router sends it to the server.
	jexec cl route -q -6 add 2001:db8:3::/64 2001:db8:1::1
	jexec rtr route -q -6 add 2001:db8:3::/64 2001:db8:2::2
	pft_set_rules rtr \
	    "pass" \
	    "pass in on ${epa}b inet6 proto tcp to 2001:db8:3::80 port 80 rdr-to 2001:db8:2::2 port 8888"
	ff_serve srv 8888

	atf_check -s exit:0 -o inline:"ff\n" \
	    jexec cl nc -6 -N -w 5 2001:db8:3::80 80
	atf_check -s exit:0 -o match:"2001:db8:2::2\[8888\] \(2001:db8:3::80\[80\]\)" \
	    jexec rtr pfctl -ss
}

rdr66_cleanup()
{
	pft_cleanup
}

atf_test_case "route_to" "cleanup"
route_to_head()
{
	atf_set descr 'route-to from the IPv6 fast forwarding path'
	atf_set require.user root
}

route_to_body()
{
	ff_topology
	# A second link to the server; its route goes over b, route-to over c.
	epc=$(vnet_mkepair)
	ifconfig ${epc}a vnet rtr
	ifconfig ${epc}b vnet srv
	jexec rtr ifconfig ${epc}a inet6 2001:db8:4::1/64 up no_dad
	jexec srv ifconfig ${epc}b inet6 2001:db8:4::2/64 up no_dad
	# OpenBSD route-to names the next hop; its route picks the interface.
	pft_set_rules rtr \
	    "pass" \
	    "pass in on ${epa}b inet6 proto tcp to 2001:db8:2::2 port 8888 route-to 2001:db8:4::2"
	ff_serve srv 8888

	atf_check -s exit:0 -o inline:"ff\n" \
	    jexec cl nc -6 -N -w 5 2001:db8:2::2 8888
	# The server saw the connection arrive on c.
	atf_check -s exit:0 -o match:"Ipkts" -o match:"${epc}b" \
	    jexec srv netstat -I ${epc}b -n
	in_c=$(jexec srv netstat -I ${epc}b -n | awk 'NR==2 {print $5}')
	[ "${in_c}" -gt 0 ] || atf_fail "nothing arrived on ${epc}b"
}

route_to_cleanup()
{
	pft_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "pass_block"
	atf_add_test_case "nat66"
	atf_add_test_case "rdr66"
	atf_add_test_case "route_to"
}
