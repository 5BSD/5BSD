#
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright © 2023 Tom Jones <thj@freebsd.org>
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

#
# Test that rdr works for TCP with IPv6.
#
#	a <-----> b <-----> c
#
# Test configures three jails (a, b and c) and connects them together with b as
# a router between a and c.
#
# TCP traffic to b on port 80 is redirected to c on port 8000
#
# Test for incorrect checksums after the rewrite by looking at a packet capture (see bug 210860)
#
tcp_v6_setup()
{
	pft_init

	j="rdr:tcp_v6"
	epair_one=$(vnet_mkepair)
	epair_two=$(vnet_mkepair)

	echo $epair_one
	echo $epair_two

	vnet_mkjail ${j}a ${epair_one}b
	vnet_mkjail ${j}b ${epair_one}a ${epair_two}a
	vnet_mkjail ${j}c ${epair_two}b

	# configure addresses for b
	jexec ${j}b ifconfig lo0 up
	jexec ${j}b ifconfig ${epair_one}a inet6 2001:db8:a::1/64 up no_dad
	jexec ${j}b ifconfig ${epair_two}a inet6 2001:db8:b::1/64 up no_dad

	# configure addresses for a
	jexec ${j}a ifconfig lo0 up
	jexec ${j}a ifconfig ${epair_one}b inet6 2001:db8:a::2/64 up no_dad

	# configure addresses for c
	jexec ${j}c ifconfig lo0 up
	jexec ${j}c ifconfig ${epair_two}b inet6 2001:db8:b::2/64 up no_dad

	# enable forwarding in the b jail
	jexec ${j}b sysctl net.inet6.ip6.forwarding=1

	# add routes so a and c can find each other
	jexec ${j}a route add -inet6 2001:db8:b::0/64 2001:db8:a::1
	jexec ${j}c route add -inet6 2001:db8:a::0/64 2001:db8:b::1

	jexec ${j}b pfctl -e
}

tcp_v6_common()
{
	pft_set_rules ${j}b "${1}"

	# Check that a can reach c over the router
	atf_check -s exit:0 -o ignore \
	    jexec ${j}a ping -6 -c 1 2001:db8:b::2

	# capture packets on c so we can look for incorrect checksums
	jexec ${j}c tcpdump -w ${PWD}/${j}.pcap tcp and port 8000 &
	tcpdumppid=$!

	# start a web server and wait until it listens (slow on emulated VMs)
	jexec ${j}c python3 -m http.server &
	for _i in $(seq 1 100); do
		jexec ${j}c sockstat -l -P tcp -p 8000 | grep -q ":8000" && break
		sleep 0.1
	done

	# http directly from a to c -> a ---> b
	atf_check -s exit:0 -o ignore \
		jexec ${j}a fetch -T 1 -o /dev/null -q "http://[2001:db8:b::2]:8000"

	# http from a to b with a redirect  -> a ---> b
	atf_check -s exit:0 -o ignore \
		jexec ${j}a fetch -T 1 -o /dev/null -q "http://[2001:db8:a::1]:80"

	# ask tcpdump to stop so we can check the packet capture
	jexec ${j}c kill -s SIGINT $tcpdumppid

	# Check for "bad tcp cksum" (OpenBSD tcpdump) in the packet capture,
	# this should tell us if checksums are bad with rdr rules
	count=$(jexec ${j}c tcpdump -vvvv -r ${PWD}/${j}.pcap | grep "bad tcp cksum" | wc -l)
	atf_check_equal "       0" "$count"
}

atf_test_case "tcp_v6_pass" "cleanup"
tcp_v6_pass_head()
{
	atf_set descr 'TCP rdr with IPv6 with pass/match rules'
	atf_set require.user root
	atf_set require.progs python3
}

tcp_v6_pass_body()
{
	tcp_v6_setup # Sets ${epair_…} variables
	tcp_v6_common \
		"pass in on ${epair_one}a proto tcp from any to any port 80 rdr-to 2001:db8:b::2 port 8000"
}

tcp_v6_pass_cleanup()
{
	pft_cleanup
}

atf_test_case "natpass" "cleanup"
natpass_head()
{
	atf_set descr 'Test rdr pass'
	atf_set require.user root
}

natpass_body()
{
	pft_init

	epair=$(vnet_mkepair)
	epair_link=$(vnet_mkepair)

	ifconfig ${epair}a 192.0.2.2/24 up

	vnet_mkjail alcatraz ${epair}b ${epair_link}a
	jexec alcatraz ifconfig lo0 inet 127.0.0.1/8 up
	jexec alcatraz ifconfig ${epair}b inet 192.0.2.1/24 up
	jexec alcatraz ifconfig ${epair_link}a 198.51.100.1/24 up
	jexec alcatraz sysctl net.inet.ip.forwarding=1

	vnet_mkjail srv ${epair_link}b
	jexec srv ifconfig ${epair_link}b inet 198.51.100.2/24 up
	jexec srv route add default 198.51.100.1

	# Sanity check
	atf_check -s exit:0 -o ignore \
	    ping -c 1 192.0.2.1
	atf_check -s exit:0 -o ignore \
	    jexec alcatraz ping -c 1 198.51.100.2

	jexec alcatraz pfctl -e
	pft_set_rules alcatraz \
	    "pass in quick on ${epair}b proto udp from any to 192.0.2.1 port 80 rdr-to 198.51.100.2" \
	    "match out on ${epair}b inet from 198.51.100.0/24 to any nat-to 192.0.2.1" \
	    "block in proto udp from any to any port 80" \
	    "pass in proto icmp"

	echo "foo" | jexec srv nc -u -l 80 &
	sleep 1 # Give the above a moment to start

	out=$(echo 1 | nc -u -w 1 192.0.2.1 80)
	echo "out ${out}"
	if [ "${out}" != "foo" ];
	then
		jexec alcatraz pfctl -sr -vv
		jexec alcatraz pfctl -ss -vv
		atf_fail "rdr failed"
	fi
}

natpass_cleanup()
{
	pft_cleanup
}

atf_test_case "pr290177" "cleanup"
pr290177_head()
{
	atf_set descr 'Test PR290177'
	atf_set require.user root
}

pr290177_body()
{
	pft_init

	epair=$(vnet_mkepair)

	ifconfig ${epair}a 192.0.2.2/24 up
	ifconfig ${epair}a inet alias 192.0.2.3/24 up

	vnet_mkjail alcatraz ${epair}b
	jexec alcatraz ifconfig ${epair}b 192.0.2.1/24 up
	jexec alcatraz ifconfig lo0 127.0.0.1/8 up

	# Sanity check
	atf_check -s exit:0 -o ignore \
	    ping -c 1 192.0.2.1

	jexec alcatraz pfctl -e
	# OpenBSD has no "no rdr"; a quick pass without rdr-to exempts the
	# sources in <white> from the redirection.
	pft_set_rules alcatraz \
	    "table <white> { 192.0.2.2 }" \
	    "pass in quick inet proto tcp from <white> to any port 25" \
	    "pass in quick inet proto tcp from any to any port 25 rdr-to 127.0.0.1 port 2500"

	echo foo | jexec alcatraz nc -N -l 2500 &
	sleep 1

	reply=$(nc -w 3 -s 192.0.2.2 192.0.2.1 25)
	if [ "${reply}" == "foo" ]
	then
		atf_fail "no rdr rule failed"
	fi
	reply=$(nc -w 3 -s 192.0.2.3 192.0.2.1 25)
	if [ "${reply}" != "foo" ]
	then
		atf_fail "rdr rule failed"
	fi
}

pr290177_cleanup()
{
	pft_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "natpass"
	atf_add_test_case "tcp_v6_pass"
	atf_add_test_case "pr290177"
}
