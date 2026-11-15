# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 The 5BSD Project
# Exercise the additional local-delivery hook, not normal loopback output.
. $(atf_get_srcdir)/../../../common/vnet.subr

local_delivery_body()
{
	family=$1
	vnet_init
	kldstat -q -m pf || atf_skip "pf is not loaded"
	host_setting=$(sysctl -n net.pf.filter_local) || atf_fail "filter_local is absent"
	e=$(vnet_mkepair)
	vnet_mkjail pflsrc ${e}a
	vnet_mkjail pfldst ${e}b
	vnet_mkjail pflother
	atf_check -s exit:0 -o inline:'0\n' jexec pfldst sysctl -n net.pf.filter_local
	atf_check -s exit:0 -o inline:'0\n' jexec pflother sysctl -n net.pf.filter_local
	jexec pflsrc ifconfig lo0 up
	jexec pfldst ifconfig lo0 up
	if [ "$family" = 4 ]; then
		src=192.0.2.1; dst=192.0.2.2; af=inet; proto=icmp
		jexec pflsrc ifconfig ${e}a inet $src/30 up
		jexec pfldst ifconfig ${e}b inet $dst/30 up
	else
		src=2001:db8:47::1; dst=2001:db8:47::2; af=inet6; proto=icmp6
		jexec pflsrc ifconfig ${e}a inet6 $src/64 no_dad up
		jexec pfldst ifconfig ${e}b inet6 $dst/64 no_dad up
	fi
	# No state on the input pass: an existing state must not hide whether
	# the additional local-delivery pass evaluated the block rule.
	printf '%s\n' \
	    "block out quick on lo0 $af proto $proto from $src to $dst label local-delivery-deny" \
	    'pass all no state' |
	    atf_check -s exit:0 -o ignore -e ignore jexec pfldst pfctl -f -
	atf_check -s exit:0 -o ignore -e ignore jexec pfldst pfctl -e
	atf_check -s exit:0 -o ignore -e ignore jexec pflsrc ping -$family -c 1 -W 3000 $dst
	atf_check -s exit:0 -o ignore jexec pfldst sysctl net.pf.filter_local=1
	atf_check -s exit:0 -o inline:'1\n' jexec pfldst sysctl -n net.pf.filter_local
	atf_check -s exit:0 -o inline:'0\n' jexec pflother sysctl -n net.pf.filter_local
	atf_check -s exit:0 -o inline:"$host_setting\n" sysctl -n net.pf.filter_local
	atf_check -s not-exit:0 -o ignore -e ignore jexec pflsrc ping -$family -c 1 -W 3000 $dst
	# Confirm a matching blocked packet, so a timed-out ping alone cannot
	# satisfy the denial test on a loaded VM.
	jexec pfldst pfctl -vvsr > rules.out
	atf_check -s exit:0 -o match:'Packets: *[1-9][0-9]*' head -n 3 rules.out
	# Toggle without PF restart; then prove disabling PF still bypasses it.
	atf_check -s exit:0 -o ignore jexec pfldst sysctl net.pf.filter_local=0
	atf_check -s exit:0 -o ignore -e ignore jexec pflsrc ping -$family -c 1 -W 3000 $dst
	atf_check -s exit:0 -o ignore jexec pfldst sysctl net.pf.filter_local=1
	atf_check -s exit:0 -o ignore -e ignore jexec pfldst pfctl -d
	atf_check -s exit:0 -o ignore -e ignore jexec pflsrc ping -$family -c 1 -W 3000 $dst
}

atf_test_case ipv4 cleanup
ipv4_head()
{
	atf_set descr 'IPv4 local-delivery filter defaults off, toggles live and is VNET-isolated'
	atf_set require.user root
}
ipv4_body() { local_delivery_body 4; }
ipv4_cleanup() { vnet_cleanup; }

atf_test_case ipv6 cleanup
ipv6_head()
{
	atf_set descr 'IPv6 local-delivery filter defaults off, toggles live and is VNET-isolated'
	atf_set require.user root
}
ipv6_body() { local_delivery_body 6; }
ipv6_cleanup() { vnet_cleanup; }


# Large loopback writes exercise TSO seeds before the local-delivery pass.
# Run in a fresh VNET so unrelated host TCP traffic cannot affect counters.
loopback_tcp_body()
{
	family=$1
	vnet_init
	kldstat -q -m pf || atf_skip "pf is not loaded"
	vnet_mkjail pfltcp
	atf_check -s exit:0 jexec pfltcp ifconfig lo0 inet 127.0.0.1/8 up
	atf_check -s exit:0 -o ignore jexec pfltcp sysctl net.inet.tcp.tso=1
	printf '%s\n' 'pass all' |
	    atf_check -s exit:0 -o ignore -e ignore jexec pfltcp pfctl -f -
	atf_check -s exit:0 -o ignore -e ignore jexec pfltcp pfctl -e
	for setting in 0 1; do
		atf_check -s exit:0 -o ignore jexec pfltcp sysctl net.pf.filter_local=$setting
		atf_check -s exit:0 -o match:'"matches": true' jexec pfltcp \
		    python3.12 $(atf_get_srcdir)/local_loopback_tcp.py $family
	done
}

atf_test_case loopback_tcp4 cleanup
loopback_tcp4_head()
{
	atf_set descr 'IPv4 loopback TSO with local filtering has no checksum failures'
	atf_set require.user root
	atf_set require.progs python3.12
}
loopback_tcp4_body() { loopback_tcp_body 4; }
loopback_tcp4_cleanup() { vnet_cleanup; }

atf_test_case loopback_tcp6 cleanup
loopback_tcp6_head()
{
	atf_set descr 'IPv6 loopback TSO with local filtering has no checksum failures'
	atf_set require.user root
	atf_set require.progs python3.12
}
loopback_tcp6_body() { loopback_tcp_body 6; }
loopback_tcp6_cleanup() { vnet_cleanup; }


# UDP exercises both odd and even checksum tails independently of TCP TSO.
loopback_udp_body()
{
	family=$1
	vnet_init
	kldstat -q -m pf || atf_skip "pf is not loaded"
	vnet_mkjail pfludp
	atf_check -s exit:0 jexec pfludp ifconfig lo0 inet 127.0.0.1/8 up
	atf_check -s exit:0 -o ignore jexec pfludp sysctl net.inet.udp.checksum=1
	printf '%s\n' 'pass all' |
	    atf_check -s exit:0 -o ignore -e ignore jexec pfludp pfctl -f -
	atf_check -s exit:0 -o ignore -e ignore jexec pfludp pfctl -e
	for setting in 0 1; do
		atf_check -s exit:0 -o ignore jexec pfludp sysctl net.pf.filter_local=$setting
		atf_check -s exit:0 -o match:'"matches": true' jexec pfludp \
		    python3.12 $(atf_get_srcdir)/local_loopback_udp.py $family
	done
}

atf_test_case loopback_udp4 cleanup
loopback_udp4_head()
{
	atf_set descr 'IPv4 loopback UDP retains valid payloads and checksums with local filtering'
	atf_set require.user root
	atf_set require.progs python3.12
}
loopback_udp4_body() { loopback_udp_body 4; }
loopback_udp4_cleanup() { vnet_cleanup; }

atf_test_case loopback_udp6 cleanup
loopback_udp6_head()
{
	atf_set descr 'IPv6 loopback UDP retains valid payloads and checksums with local filtering'
	atf_set require.user root
	atf_set require.progs python3.12
}
loopback_udp6_body() { loopback_udp_body 6; }
loopback_udp6_cleanup() { vnet_cleanup; }

atf_init_test_cases()
{
	atf_add_test_case ipv4
	atf_add_test_case ipv6
	atf_add_test_case loopback_tcp4
	atf_add_test_case loopback_tcp6
	atf_add_test_case loopback_udp4
	atf_add_test_case loopback_udp6
}
