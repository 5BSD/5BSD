#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 The 5BSD Project
#
# OpenBSD ifconfig(8) behaviour adopted by 5BSD: implicit creation of a
# cloneable interface that is configured before it exists, the
# "no such interface" message, and the status output format.

. $(atf_get_srcdir)/../../sys/common/vnet.subr

atf_test_case "autocreate" "cleanup"
autocreate_head()
{
	atf_set descr "Configuring a cloneable interface that does not exist creates it"
	atf_set require.user root
}
autocreate_body()
{
	vnet_init
	vnet_mkjail one
	# A new vnet has only lo0.
	lo=lo4100

	atf_check -s exit:0 -o empty jexec one ifconfig ${lo} inet 192.0.2.1/32 up
	atf_check -s exit:0 -o match:"^${lo}: flags=.*<UP" jexec one ifconfig ${lo}
	atf_check -s exit:0 -o match:"inet 192\.0\.2\.1 " jexec one ifconfig ${lo}
	atf_check -s exit:0 jexec one ifconfig ${lo} destroy
}
autocreate_cleanup()
{
	vnet_cleanup
}

atf_test_case "nocreate" "cleanup"
nocreate_head()
{
	atf_set descr "Listing or destroying an interface that does not exist does not create it"
	atf_set require.user root
}
nocreate_body()
{
	vnet_init
	vnet_mkjail one

	# OpenBSD wording, without a program name prefix.
	atf_check -s not-exit:0 -o empty -e inline:"lo4999: no such interface\n" \
	    jexec one ifconfig lo4999
	atf_check -s not-exit:0 -o empty -e not-empty \
	    jexec one ifconfig lo4999 destroy
	atf_check -s not-exit:0 -o empty -e ignore jexec one ifconfig lo4999
	# Names that do not end in a digit are never created implicitly.
	atf_check -s not-exit:0 -o empty -e ignore jexec one ifconfig lofoo up
	# Unknown drivers cannot be created.
	atf_check -s not-exit:0 -o empty -e ignore \
	    jexec one ifconfig nonexistent0 192.0.2.1/24
}
nocreate_cleanup()
{
	vnet_cleanup
}

atf_test_case "format" "cleanup"
format_head()
{
	atf_set descr "Status lines follow OpenBSD ifconfig(8)"
	atf_set require.user root
}
format_body()
{
	local epair

	vnet_init
	epair=$(vnet_mkepair)
	vnet_mkjail one ${epair}a
	jexec one ifconfig ${epair}a inet 192.0.2.1/24 up
	jexec one ifconfig ${epair}a group testgrp
	jexec one ifconfig ${epair}a > out

	# Header: flags, no " metric 0", mtu.
	atf_check -s exit:0 -o match:"^${epair}a: flags=[0-9a-f]+<.*> mtu 1500$" \
	    head -n 1 out
	# Ethernet address as "lladdr", then "index".
	atf_check -s exit:0 -o match:"^	lladdr [0-9a-f:]{17}$" sed -n 2p out
	atf_check -s exit:0 -o match:"^	index [0-9]+$" sed -n 3p out
	# groups: and media: precede the addresses.
	g=$(grep -n '^	groups:' out | cut -d: -f1)
	m=$(grep -n '^	media:' out | cut -d: -f1)
	i=$(grep -n '^	inet 192\.0\.2\.1 ' out | cut -d: -f1)
	[ -n "$g" ] && [ -n "$m" ] && [ -n "$i" ] || atf_fail "missing line"
	[ "$g" -lt "$m" ] && [ "$m" -lt "$i" ] || atf_fail "wrong order"
	atf_check -s exit:0 -o match:"testgrp" grep '^	groups:' out
	atf_check -s not-exit:0 grep -q 'metric 0' out
	atf_check -s not-exit:0 grep -q '^	ether ' out
	# "ether" still selects the link-level address.
	atf_check -s exit:0 -o match:"^	lladdr " jexec one ifconfig ${epair}a ether
}
format_cleanup()
{
	vnet_cleanup
}

atf_test_case "extended_flags" "cleanup"
extended_flags_head()
{
	atf_set descr "Extended flags retain their OpenBSD numeric positions"
	atf_set require.user root
}
extended_flags_body()
{
	vnet_init
	vnet_mkjail one
	atf_check jexec one ifconfig lo0 up monitor
	atf_check -o match:'^lo0: flags=1008049<UP,LOOPBACK,RUNNING,MULTICAST,MONITOR>' \
	    jexec one ifconfig lo0
	atf_check jexec one ifconfig lo0 -monitor
	atf_check -o match:'^lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST>' \
	    jexec one ifconfig lo0
}
extended_flags_cleanup()
{
	vnet_cleanup
}

atf_test_case "pflow" "cleanup"
pflow_head()
{
	atf_set descr "pflow(4) is created implicitly and shown as on OpenBSD"
	atf_set require.user root
}
pflow_body()
{
	if ! kldstat -q -m pf; then
		atf_skip "pf(4) is not loaded"
	fi
	vnet_init
	vnet_mkjail one

	atf_check -s exit:0 jexec one ifconfig pflow0 flowsrc 127.0.0.1 \
	    flowdst 127.0.0.1:9996
	jexec one ifconfig pflow0 | grep -v '^[[:space:]]index' > out
	printf 'pflow0: flags=41<UP,RUNNING> mtu 1492\n\tpflow: sender: 127.0.0.1 receiver: 127.0.0.1:9996 version: 5\n\tgroups: pflow\n' > exp
	atf_check -s exit:0 diff -u exp out
	atf_check -s exit:0 jexec one ifconfig pflow0 destroy
	atf_check -s not-exit:0 -e inline:"pflow0: no such interface\n" \
	    jexec one ifconfig pflow0
}
pflow_cleanup()
{
	vnet_cleanup
}

atf_test_case "inet_mask" "cleanup"
inet_mask_head()
{
	atf_set descr "IPv4 prefixlen, contiguous netmasks and /32 broadcast as OpenBSD"
	atf_set require.user root
}
inet_mask_body()
{
	local epair

	vnet_init
	epair=$(vnet_mkepair)
	vnet_mkjail one ${epair}a

	atf_check jexec one ifconfig ${epair}a inet 192.0.2.1 prefixlen 24
	atf_check -o match:"inet 192\.0\.2\.1 netmask 0xffffff00 broadcast 192\.0\.2\.255$" \
	    jexec one ifconfig ${epair}a
	atf_check jexec one ifconfig ${epair}a inet 192.0.2.1 delete

	atf_check -s exit:1 -e match:"non-contiguous netmask" \
	    jexec one ifconfig ${epair}a inet 192.0.2.1 netmask 255.255.255.64
	atf_check -o not-match:"inet 192\.0\.2\.1 " jexec one ifconfig ${epair}a

	# No broadcast address is shown for a host address.
	atf_check jexec one ifconfig ${epair}a inet 192.0.2.1/24
	atf_check jexec one ifconfig ${epair}a inet 192.0.2.1/32
	atf_check -o match:"inet 192\.0\.2\.1 netmask 0xffffffff$" \
	    jexec one ifconfig ${epair}a
	atf_check jexec one ifconfig ${epair}a inet 192.0.2.2/32 alias
	atf_check -o match:"inet 192\.0\.2\.2 netmask 0xffffffff$" \
	    jexec one ifconfig ${epair}a
	# A broadcast address set explicitly is shown.
	atf_check jexec one ifconfig ${epair}a inet 192.0.2.3/32 \
	    broadcast 192.0.2.255 alias
	atf_check -o match:"inet 192\.0\.2\.3 netmask 0xffffffff broadcast 192\.0\.2\.255$" \
	    jexec one ifconfig ${epair}a
}
inet_mask_cleanup()
{
	vnet_cleanup
}

atf_test_case "p2p_nodst" "cleanup"
p2p_nodst_head()
{
	atf_set descr "Point-to-point addresses without or sharing a destination"
	atf_set require.user root
}
p2p_nodst_body()
{
	local tun

	vnet_init
	vnet_mkjail one
	tun=$(jexec one ifconfig tun create)

	atf_check jexec one ifconfig ${tun} inet 192.0.2.1/24
	atf_check -o match:"inet 192\.0\.2\.1 --> 0\.0\.0\.0 netmask 0xffffff00$" \
	    jexec one ifconfig ${tun}
	atf_check jexec one ifconfig ${tun} inet 192.0.2.1/24 192.0.2.2
	atf_check -o match:"inet 192\.0\.2\.1 --> 192\.0\.2\.2 netmask 0xffffff00$" \
	    jexec one ifconfig ${tun}

	atf_check jexec one ifconfig ${tun} inet6 2001:db8::1/64
	atf_check -o match:"inet6 2001:db8::1 --> :: prefixlen 64" \
	    jexec one ifconfig ${tun}

	# A destination implies prefixlen 128; addresses may share it.
	atf_check jexec one ifconfig ${tun} inet6 2001:db8:1::1 2001:db8:1::ff
	atf_check jexec one ifconfig ${tun} inet6 2001:db8:1::2 2001:db8:1::ff alias
	atf_check -o match:"inet6 2001:db8:1::1 --> 2001:db8:1::ff prefixlen 128" \
	    jexec one ifconfig ${tun}
	atf_check -o match:"inet6 2001:db8:1::2 --> 2001:db8:1::ff prefixlen 128" \
	    jexec one ifconfig ${tun}
	# The route to the peer moves to the remaining address.
	atf_check jexec one ifconfig ${tun} inet6 2001:db8:1::1 delete
	atf_check -o match:"interface: ${tun}" \
	    jexec one route -n get -inet6 2001:db8:1::ff
}
p2p_nodst_cleanup()
{
	vnet_cleanup
}

atf_test_case "inet6_attach" "cleanup"
inet6_attach_head()
{
	atf_set descr "eui64 attaches IPv6; a first address is tentative"
	atf_set require.user root
}
inet6_attach_body()
{
	local epair

	vnet_init
	epair=$(vnet_mkepair)
	vnet_mkjail one ${epair}a ${epair}b

	# "eui64" creates the link-local address, as OpenBSD.
	atf_check jexec one ifconfig ${epair}a inet6 eui64
	atf_check -o match:"inet6 fe80::[0-9a-f:]*%${epair}a " \
	    jexec one ifconfig ${epair}a

	# The first address of an interface still without IPv6 gets DAD.
	atf_check jexec one ifconfig ${epair}b inet6 2001:db8::2/64
	atf_check -o match:"inet6 2001:db8::2 prefixlen 64 tentative" \
	    jexec one ifconfig ${epair}b
}
inet6_attach_cleanup()
{
	vnet_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case autocreate
	atf_add_test_case nocreate
	atf_add_test_case format
	atf_add_test_case extended_flags
	atf_add_test_case pflow
	atf_add_test_case inet_mask
	atf_add_test_case p2p_nodst
	atf_add_test_case inet6_attach
}
