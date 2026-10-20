#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 The 5BSD Project
#
# The OpenBSD "egress" interface group: the interfaces holding a default
# route in routing table 0, and pf rules naming it.

. $(atf_get_srcdir)/utils.subr

# The group is rebuilt by a task after the route change; poll briefly.
# egress_wait jail "expected members, sorted, space separated"
egress_wait()
{
	local j=$1 want=$2 got i

	for i in $(seq 1 50); do
		got=$(jexec ${j} ifconfig -g egress | sort | xargs)
		[ "${got}" = "${want}" ] && return 0
		sleep 0.1
	done
	atf_fail "egress in ${j}: got '${got}', expected '${want}'"
}

atf_test_case "group" "cleanup"
group_head()
{
	atf_set descr 'egress follows the default routes of FIB 0, per vnet'
	atf_set require.user root
}

group_body()
{
	pft_init

	epair_a=$(vnet_mkepair)
	epair_b=$(vnet_mkepair)
	vnet_mkjail alcatraz ${epair_a}a ${epair_b}a
	vnet_mkjail other

	jexec alcatraz ifconfig lo0 127.0.0.1/8 up
	jexec alcatraz ifconfig ${epair_a}a 192.0.2.2/24 up
	jexec alcatraz ifconfig ${epair_a}a inet6 2001:db8:a::2/64 up no_dad
	jexec alcatraz ifconfig ${epair_b}a 198.51.100.2/24 up
	jexec alcatraz ifconfig ${epair_b}a inet6 2001:db8:b::2/64 up no_dad

	egress_wait alcatraz ""

	# IPv4 default route.
	atf_check -o ignore jexec alcatraz route add default 192.0.2.1
	egress_wait alcatraz "${epair_a}a"
	# Another vnet is not affected.
	egress_wait other ""

	# Moving the default route moves the group.
	atf_check -o ignore jexec alcatraz route change default 198.51.100.1
	egress_wait alcatraz "${epair_b}a"

	# IPv6 default route on the other interface: both are members.
	atf_check -o ignore jexec alcatraz route add -inet6 default 2001:db8:a::1
	egress_wait alcatraz "$(printf '%s\n' ${epair_a}a ${epair_b}a | sort | xargs)"

	# Deleting the routes empties the group.
	atf_check -o ignore jexec alcatraz route delete default
	egress_wait alcatraz "${epair_a}a"
	atf_check -o ignore jexec alcatraz route delete -inet6 default
	egress_wait alcatraz ""

	# A blackhole default route does not count.
	atf_check -o ignore jexec alcatraz \
	    route add default 127.0.0.1 -blackhole
	egress_wait alcatraz ""
	atf_check -o ignore jexec alcatraz route delete default

	# A default route in another FIB does not count either.
	if [ "$(jexec alcatraz sysctl -n net.fibs)" -lt 2 ]; then
		jexec alcatraz sysctl net.fibs=2 >/dev/null 2>&1 || true
	fi
	if [ "$(jexec alcatraz sysctl -n net.fibs)" -ge 2 ]; then
		atf_check -o ignore jexec alcatraz \
		    setfib 1 route add default 192.0.2.1
		sleep 0.5
		egress_wait alcatraz ""
	fi
}

group_cleanup()
{
	pft_cleanup
}

atf_test_case "pf" "cleanup"
pf_head()
{
	atf_set descr 'pf matches "on egress" and "(egress)" as the group changes'
	atf_set require.user root
}

pf_body()
{
	pft_init

	epair=$(vnet_mkepair)
	ifconfig ${epair}b 192.0.2.1/24 up
	vnet_mkjail alcatraz ${epair}a
	jexec alcatraz ifconfig ${epair}a 192.0.2.2/24 up

	# Sanity: reachable without pf.
	atf_check -o ignore jexec alcatraz ping -c1 -t1 192.0.2.1

	atf_check -o ignore jexec alcatraz route add default 192.0.2.1
	egress_wait alcatraz "${epair}a"

	jexec alcatraz pfctl -e
	pft_set_rules alcatraz \
	    "set skip on lo0" \
	    "block out all" \
	    "pass out on egress inet from (egress) to any"

	# The interface is in egress: traffic leaves.
	atf_check -o ignore jexec alcatraz ping -c1 -t1 192.0.2.1

	# Without the default route it is no longer in egress.
	atf_check -o ignore jexec alcatraz route delete default
	egress_wait alcatraz ""
	jexec alcatraz pfctl -F states >/dev/null 2>&1
	atf_check -s not-exit:0 -o ignore -e ignore \
	    jexec alcatraz ping -c1 -t1 192.0.2.1

	# And again with the route restored, without reloading the rules.
	atf_check -o ignore jexec alcatraz route add default 192.0.2.1
	egress_wait alcatraz "${epair}a"
	atf_check -o ignore jexec alcatraz ping -c1 -t1 192.0.2.1
}

pf_cleanup()
{
	pft_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "group"
	atf_add_test_case "pf"
}
