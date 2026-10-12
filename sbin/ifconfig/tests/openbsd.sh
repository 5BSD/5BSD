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

atf_init_test_cases()
{
	atf_add_test_case autocreate
	atf_add_test_case nocreate
	atf_add_test_case format
	atf_add_test_case pflow
}
