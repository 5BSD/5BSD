#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 The 5BSD Project
#
# OpenBSD PF per-vnet instances: every vnet has its own rulesets, states,
# tables, anchors, interfaces and pflog/pfsync/pflow clones, and /dev/pf
# acts on the vnet of the process that opened it.

. $(atf_get_srcdir)/../../../common/vnet.subr

pf_vnet_init()
{
	vnet_init
	if ! kldstat -q -m pf; then
		atf_skip "pf is not loaded"
	fi
}

# pool_inuse <pool>: in-use count from the OpenBSD style pool listing.
pool_inuse()
{
	vmstat -m -v | awk -v p="$1" '$1 == p { print $5 }'
}

# setup_pair <jail> <epair> <host addr> <jail addr>
setup_pair()
{
	ifconfig $2a inet $3/30 up
	jexec $1 ifconfig $2b inet $4/30 up
	jexec $1 ifconfig lo0 inet 127.0.0.1/8 up
}

atf_test_case "isolation" "cleanup"
isolation_head()
{
	atf_set descr 'Rulesets, tables, anchors, status and states are per vnet'
	atf_set require.user root
}

isolation_body()
{
	pf_vnet_init

	e1=$(vnet_mkepair)
	e2=$(vnet_mkepair)
	vnet_mkjail pfv1 ${e1}b
	vnet_mkjail pfv2 ${e2}b
	vnet_mkjail pfv3
	setup_pair pfv1 ${e1} 192.0.2.1 192.0.2.2
	setup_pair pfv2 ${e2} 192.0.2.5 192.0.2.6

	printf 'table <hosttab> persist { 198.51.100.1 }\npass all\nanchor "hostanchor"\n' |
	    atf_check -s exit:0 -o ignore -e ignore pfctl -f -
	pfctl -e >/dev/null 2>&1 || true

	printf 'table <v1tab> persist { 198.51.100.2 }\nblock in proto icmp all\npass out all\n' |
	    atf_check -s exit:0 -o ignore -e ignore jexec pfv1 pfctl -f -
	atf_check -s exit:0 -o ignore -e ignore jexec pfv1 pfctl -e

	printf 'table <v2tab> persist { 198.51.100.3 }\npass all\nanchor "v2anchor"\n' |
	    atf_check -s exit:0 -o ignore -e ignore jexec pfv2 pfctl -f -
	atf_check -s exit:0 -o ignore -e ignore jexec pfv2 pfctl -e

	# Packet filtering follows the vnet's own ruleset.
	atf_check -s not-exit:0 -o ignore -e ignore ping -c 1 -W 1000 192.0.2.2
	atf_check -s exit:0 -o ignore ping -c 1 -W 1000 192.0.2.6

	# Tables and anchors.
	atf_check -s exit:0 -o match:'hosttab' -o not-match:'v1tab' \
	    -o not-match:'v2tab' pfctl -sT
	atf_check -s exit:0 -o match:'v1tab' -o not-match:'hosttab' \
	    -o not-match:'v2tab' jexec pfv1 pfctl -sT
	atf_check -s exit:0 -o match:'v2tab' -o not-match:'v1tab' \
	    jexec pfv2 pfctl -sT
	atf_check -s exit:0 -o match:'hostanchor' -o not-match:'v2anchor' \
	    pfctl -sA
	atf_check -s exit:0 -o match:'v2anchor' -o not-match:'hostanchor' \
	    jexec pfv2 pfctl -sA
	atf_check -s exit:0 -o empty jexec pfv1 pfctl -sA

	# Rulesets.
	atf_check -s exit:0 -o match:'block' jexec pfv1 pfctl -sr
	atf_check -s exit:0 -o not-match:'block' jexec pfv2 pfctl -sr
	atf_check -s exit:0 -o not-match:'block' pfctl -sr

	# Status: a fresh vnet starts disabled with an empty ruleset.
	atf_check -s exit:0 -o match:'Status: Disabled' jexec pfv3 pfctl -si
	atf_check -s exit:0 -o empty jexec pfv3 pfctl -sr
	atf_check -s exit:0 -o match:'Status: Enabled' jexec pfv2 pfctl -si

	# States: the ping to pfv2 created a state there, none in pfv1.
	atf_check -s exit:0 -o match:'192.0.2.6' jexec pfv2 pfctl -ss
	atf_check -s exit:0 -o not-match:'192.0.2.6' jexec pfv1 pfctl -ss

	# Interfaces: each vnet only knows its own.
	atf_check -s exit:0 -o match:"${e1}b" -o not-match:"${e2}b" \
	    jexec pfv1 pfctl -sI
	atf_check -s exit:0 -o not-match:"${e1}b" pfctl -sI
}

isolation_cleanup()
{
	pfctl -a hostanchor -Fa >/dev/null 2>&1
	pfctl -Fa >/dev/null 2>&1
	vnet_cleanup
}

atf_test_case "limits" "cleanup"
limits_head()
{
	atf_set descr 'Pool limits are owned by the host vnet'
	atf_set require.user root
}

limits_body()
{
	pf_vnet_init
	vnet_mkjail pfvl

	cur=$(pfctl -sm | awk '$1 == "states" { print $4 }')
	[ -n "$cur" ] || atf_fail "no states limit in pfctl -sm"
	echo "set limit states ${cur}" |
	    atf_check -s exit:0 -o ignore -e ignore jexec pfvl pfctl -f -
	echo "set limit states $((cur + 1000))" |
	    atf_check -s not-exit:0 -o ignore -e ignore jexec pfvl pfctl -f -
	atf_check -s exit:0 -o match:"states.*hard limit.*${cur}" pfctl -sm
}

limits_cleanup()
{
	vnet_cleanup
}

atf_test_case "clones" "cleanup"
clones_head()
{
	atf_set descr 'pflog, pfsync and pflow interfaces are per vnet'
	atf_set require.user root
}

clones_body()
{
	pf_vnet_init
	vnet_mkjail pfvc

	atf_check -s exit:0 -o ignore jexec pfvc ifconfig pflog0 create
	atf_check -s exit:0 -o ignore jexec pfvc ifconfig pfsync0 create
	atf_check -s exit:0 -o ignore jexec pfvc ifconfig pflow0 create
	atf_check -s exit:0 -o ignore ifconfig pflog7 create
	atf_check -s not-exit:0 -o ignore -e ignore ifconfig pflow0
	atf_check -s not-exit:0 -o ignore -e ignore jexec pfvc ifconfig pflog7

	# Removing the jail destroys its clones and leaves the host's alone.
	atf_check -s exit:0 jail -r pfvc
	sed -i '' '/^pfvc/d' created_jails.lst
	atf_check -s exit:0 -o ignore ifconfig pflog7
	atf_check -s exit:0 -o ignore ifconfig pflog7 destroy
}

clones_cleanup()
{
	ifconfig pflog7 destroy >/dev/null 2>&1
	vnet_cleanup
}

atf_test_case "teardown_live_states" "cleanup"
teardown_live_states_head()
{
	atf_set descr 'Removing vnet jails with live states, tables and anchors leaks nothing'
	atf_set require.user root
	atf_set timeout 900
}

teardown_live_states_body()
{
	pf_vnet_init
	# The host keeps this one-rule ruleset throughout.
	echo 'pass all' | pfctl -f - >/dev/null 2>&1

	base_states=$(pool_inuse pfstate)
	base_keys=$(pool_inuse pfstkey)
	base_rules=$(pool_inuse pfrule)
	base_tables=$(pool_inuse pfrktable)
	base_anchors=$(pool_inuse pfanchor)
	base_frags=$(pool_inuse pffrent)

	i=0
	while [ $i -lt 10 ]; do
		e=$(vnet_mkepair)
		vnet_mkjail pfvt$i ${e}b
		setup_pair pfvt$i ${e} 192.0.2.9 192.0.2.10
		printf '%s\n' \
		    'table <t> persist { 198.51.100.0/24 203.0.113.1 }' \
		    'pass all keep state (max-src-states 100, source-track rule)' \
		    'anchor "a" {' 'anchor "b" {' 'pass in proto tcp to port 7' \
		    '}' '}' \
		    'pass in proto udp to port 9 keep state' |
		    jexec pfvt$i pfctl -f - >/dev/null 2>&1 ||
		    atf_fail "ruleset load in pfvt$i"
		jexec pfvt$i pfctl -e >/dev/null 2>&1

		# ICMP, UDP and a TCP connection that stays open.
		ping -c 2 -i 0.2 192.0.2.10 >/dev/null 2>&1
		jexec pfvt$i nc -l 192.0.2.10 7 >/dev/null 2>&1 &
		sleep 0.3
		(sleep 30 | nc 192.0.2.10 7 >/dev/null 2>&1 &)
		echo x | nc -u -w 1 192.0.2.10 9 >/dev/null 2>&1
		# Fragments kept in the reassembly queue: first halves only.
		ping -c 1 -s 3000 192.0.2.10 >/dev/null 2>&1
		sleep 0.5
		n=$(jexec pfvt$i pfctl -ss 2>/dev/null | wc -l)
		[ "$n" -gt 0 ] || atf_fail "no states in pfvt$i"

		ifconfig ${e}a destroy
		unlist_interface ${e}a
		jail -r pfvt$i || atf_fail "jail -r pfvt$i"
		sed -i '' "/^pfvt$i /d" created_jails.lst
		i=$((i + 1))
	done

	pkill -f 'nc 192.0.2.10 7' >/dev/null 2>&1
	pfctl -k 0.0.0.0/0 >/dev/null 2>&1
	pfctl -F states >/dev/null 2>&1

	# Removed jails linger (dying) until their TIME_WAIT connections
	# expire; their vnet, and its pf, goes away after that.
	i=0
	while jls -d name 2>/dev/null | grep -q '^pfvt'; do
		i=$((i + 1))
		[ $i -lt 240 ] || atf_fail "dying jails did not go away"
		sleep 1
	done
	# The host's flushed states are freed by its purge task.
	sleep 12

	for p in pfstate:$base_states pfstkey:$base_keys pfrule:$base_rules \
	    pfrktable:$base_tables pfanchor:$base_anchors \
	    pffrent:$base_frags; do
		name=${p%%:*}
		base=${p#*:}
		now=$(pool_inuse $name)
		[ "${now:-0}" -le "${base:-0}" ] ||
		    atf_fail "pool $name in use $base -> $now after teardown"
	done
	atf_check -s exit:0 -o not-match:'torn down with' dmesg
}

teardown_live_states_cleanup()
{
	pkill -f 'nc 192.0.2.10 7' >/dev/null 2>&1
	pfctl -Fa >/dev/null 2>&1
	vnet_cleanup
}

atf_test_case "nested" "cleanup"
nested_head()
{
	atf_set descr 'A vnet jail inside a vnet jail runs its own pf'
	atf_set require.user root
}

nested_body()
{
	pf_vnet_init

	e=$(vnet_mkepair)
	jail -c name=pfvo persist vnet children.max=4 vnet.interface=${e}b
	echo "pfvo ${e}b" >> created_jails.lst
	unlist_interface ${e}b
	setup_pair pfvo ${e} 192.0.2.13 192.0.2.14
	atf_check -s exit:0 jexec pfvo jail -c name=inner persist vnet

	echo 'block all' | atf_check -s exit:0 -o ignore -e ignore \
	    jexec pfvo.inner pfctl -f -
	atf_check -s exit:0 -o ignore -e ignore jexec pfvo.inner pfctl -e
	atf_check -s exit:0 -o empty jexec pfvo pfctl -sr
	atf_check -s exit:0 -o match:'Status: Disabled' jexec pfvo pfctl -si
	atf_check -s exit:0 -o ignore ping -c 1 -W 1000 192.0.2.14
	atf_check -s exit:0 -o match:'block' jexec pfvo.inner pfctl -sr

	atf_check -s exit:0 jexec pfvo jail -r inner
}

nested_cleanup()
{
	jexec pfvo jail -r inner >/dev/null 2>&1
	vnet_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "isolation"
	atf_add_test_case "limits"
	atf_add_test_case "clones"
	atf_add_test_case "teardown_live_states"
	atf_add_test_case "nested"
}
