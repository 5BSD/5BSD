#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 5BSD
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

# Address pools backed by tables (pf_lb.c / pf_table.c), table
# administration and RFC 6052 address family translation
# (inet_nat64.c).  OpenBSD pf semantics: the last matching rule wins.

. $(atf_get_srcdir)/utils.subr

common_dir=$(atf_get_srcdir)/../common

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Start an inetd with the discard service in jail $1 (family tcp or tcp6).
pools_inetd()
{
	conf=$(mktemp) || exit 1
	echo "discard stream $2 nowait root internal" > ${conf}
	jexec $1 inetd -p ${PWD}/inetd_$1.pid ${conf}
}

# NAT44 fixture:
#   tester (this vnet) 192.0.2.2 --- 192.0.2.1 rtr 198.51.100.1 --- srv .2
# Clients use the non-local sources 203.0.113.0/25 (routed to the tester,
# which does not own them, so its stack never answers with an RST); the
# translation pools live in 203.0.113.128/25, routed back by srv.
pools_nat44_setup()
{
	pft_init

	epair_lan=$(vnet_mkepair)
	epair_wan=$(vnet_mkepair)

	ifconfig ${epair_lan}a 192.0.2.2/24 up
	route add -net 198.51.100.0/24 192.0.2.1

	vnet_mkjail rtr ${epair_lan}b ${epair_wan}a
	jexec rtr ifconfig ${epair_lan}b 192.0.2.1/24 up
	jexec rtr ifconfig ${epair_wan}a 198.51.100.1/24 up
	jexec rtr sysctl net.inet.ip.forwarding=1 > /dev/null
	jexec rtr route add -net 203.0.113.0/25 192.0.2.2

	vnet_mkjail srv ${epair_wan}b
	jexec srv ifconfig ${epair_wan}b 198.51.100.2/24 up
	jexec srv route add -net 203.0.113.128/25 198.51.100.1
	pools_inetd srv tcp

	atf_check -s exit:0 -o ignore ping -c 1 -t 2 192.0.2.1
	atf_check -s exit:0 -o ignore jexec srv ping -c 1 -t 2 198.51.100.1

	jexec rtr pfctl -e
}

# One TCP handshake from source $1 port $2 to $3 through ${epair_lan}a.
pools_conn()
{
	atf_check -s exit:0 ${common_dir}/pft_ping.py \
	    --sendif ${epair_lan}a --replyif ${epair_lan}a \
	    --fromaddr $1 --to $3 --ping-type=tcp3way --send-sport=$2
}

# Translated source address of the state whose original source is $2
# ("addr:port" for IPv4, "addr[port]" for IPv6) in jail $1.
pools_nat_addr()
{
	jexec $1 pfctl -ss | grep -F "($2)" | awk '{ print $3 }' | \
	    sed -E 's/\[[0-9]+\]$//; s/^([0-9.]+):[0-9]+$/\1/' | head -n 1
}

# Value of the per-address field $4 ("Active States:", "Weight:") of
# address $3 in table $2 of jail $1, as printed by pfctl -T show -v.
# Prints 0 when pfctl leaves the field out (no states, no weight).
pools_tbl_field()
{
	v=$(jexec $1 pfctl -t $2 -T show -v | awk -v a="$3" -v f="$4" '
	    /^[^\t]/ { cur = $1 }
	    cur == a && index($0, f) { print $NF }')
	echo ${v:-0}
}

# Count occurrences of word $1 in the remaining arguments.
pools_count()
{
	w=$1
	shift
	n=0
	for x in "$@"; do
		[ "${x}" = "${w}" ] && n=$((n + 1))
	done
	echo ${n}
}

# Route-to fixture shared with route_to.sh's pf_map_addr tests: two
# servers behind the router, each with extra on-link next-hop aliases
# ${net_serverN_6}::42:{0,1,4,5}.
pools_rt_setup()
{
	setup_router_server_nat64

	jexec router route add -6 ${net_clients_6}::/${net_clients_6_mask} \
	    ${net_tester_6_host_tester}
	for i in 0 1 4 5; do
		jexec server1 ifconfig ${epair_server1}b inet6 \
		    ${net_server1_6}::42:${i}/128 alias
		jexec server2 ifconfig ${epair_server2}b inet6 \
		    ${net_server2_6}::42:${i}/128 alias
	done
}

pools_rt_conn()
{
	atf_check -s exit:0 ${common_dir}/pft_ping.py \
	    --sendif ${epair_tester}a --replyif ${epair_tester}a \
	    --fromaddr $1 --to ${host_server_6} \
	    --ping-type=tcp3way --send-sport=$2
}

# Route-to next hop ({...}) of the inbound state from client $1 port $2.
pools_rt_target()
{
	jexec router pfctl -ss | grep -F "<- $1[$2]" | \
	    sed -nE 's/.*\{([^}]*)\}.*/\1/p' | head -n 1
}

# ---------------------------------------------------------------------------
# Address pools from tables
# ---------------------------------------------------------------------------

atf_test_case "nat_least_states" "cleanup"
nat_least_states_head()
{
	atf_set descr 'nat-to <table> least-states follows per-entry state counts'
	atf_set require.user root
	atf_set require.progs python3 scapy
	atf_set timeout 300
}

nat_least_states_body()
{
	# pf_map_addr PF_POOL_LEASTSTATES, pfr_pool_get, pfr_kentry_byidx,
	# pf_map_addr_states_increase/pfr_states_increase and, on state
	# removal, pf_postprocess_addr/pf_pool_states_decrease_addr/
	# pfr_states_decrease.
	pools_nat44_setup

	pft_set_rules rtr \
	    "table <pool> { 203.0.113.130 203.0.113.131 }" \
	    "pass" \
	    "pass out on ${epair_wan}a inet proto tcp from 203.0.113.0/25 nat-to <pool> least-states"

	pools_conn 203.0.113.1 4201 198.51.100.2
	pools_conn 203.0.113.2 4202 198.51.100.2

	a1=$(pools_nat_addr rtr 203.0.113.1:4201)
	a2=$(pools_nat_addr rtr 203.0.113.2:4202)
	echo "a1=${a1} a2=${a2}"
	[ "${a1}" = "203.0.113.130" ] || atf_fail "first state used '${a1}'"
	[ "${a2}" = "203.0.113.131" ] || atf_fail "second state used '${a2}'"

	jexec rtr pfctl -t pool -T show -v
	[ $(pools_tbl_field rtr pool 203.0.113.130 "Active States:") -eq 1 ] ||
	    atf_fail "203.0.113.130 does not count 1 state"
	[ $(pools_tbl_field rtr pool 203.0.113.131 "Active States:") -eq 1 ] ||
	    atf_fail "203.0.113.131 does not count 1 state"

	# Removing the states of the second client gives its pool address
	# back; least-states must now pick it although the pool counter
	# points at the first address.
	atf_check -s exit:0 -o ignore -e ignore jexec rtr pfctl -k 203.0.113.2
	jexec rtr pfctl -t pool -T show -v
	[ $(pools_tbl_field rtr pool 203.0.113.131 "Active States:") -eq 0 ] ||
	    atf_fail "203.0.113.131 state count was not decreased"
	[ $(pools_tbl_field rtr pool 203.0.113.130 "Active States:") -eq 1 ] ||
	    atf_fail "203.0.113.130 state count changed"

	pools_conn 203.0.113.3 4203 198.51.100.2
	a3=$(pools_nat_addr rtr 203.0.113.3:4203)
	echo "a3=${a3}"
	[ "${a3}" = "203.0.113.131" ] ||
	    atf_fail "least-states chose '${a3}', not the idle 203.0.113.131"
	[ $(pools_tbl_field rtr pool 203.0.113.131 "Active States:") -eq 1 ] ||
	    atf_fail "203.0.113.131 does not count the new state"
}

nat_least_states_cleanup()
{
	pft_cleanup
}

atf_test_case "nat_round_robin_weighted" "cleanup"
nat_round_robin_weighted_head()
{
	atf_set descr 'Weighted round-robin over a table, weights from pf.conf and pfctl'
	atf_set require.user root
	atf_set require.progs python3 scapy
	atf_set timeout 300
}

nat_round_robin_weighted_body()
{
	# Weighted entries (PFRKE_COST): pfr_ktable_winfo_update/pfr_gcd
	# (weights 4, 2 and 6 give gcd 2), the curweight walk in
	# pfr_pool_get and the weighted PF_POOL_ROUNDROBIN loop in
	# pf_map_addr; pfr_copyout_addr reports the weights.
	pools_nat44_setup

	pft_set_rules rtr \
	    "table <pool> { 203.0.113.130 weight 4, 203.0.113.131 weight 2 }" \
	    "pass" \
	    "pass out on ${epair_wan}a inet proto tcp from 203.0.113.0/25 nat-to <pool> round-robin"

	# Command-line weight syntax ("addr weight N").
	atf_check -s exit:0 -e match:"1/1 addresses added" \
	    jexec rtr pfctl -t pool -T add 203.0.113.132 weight 6

	jexec rtr pfctl -t pool -T show -v
	[ $(pools_tbl_field rtr pool 203.0.113.130 "Weight:") -eq 4 ] ||
	    atf_fail "203.0.113.130 lost weight 4"
	[ $(pools_tbl_field rtr pool 203.0.113.131 "Weight:") -eq 2 ] ||
	    atf_fail "203.0.113.131 lost weight 2"
	[ $(pools_tbl_field rtr pool 203.0.113.132 "Weight:") -eq 6 ] ||
	    atf_fail "203.0.113.132 lost weight 6"

	chosen=""
	for p in 1 2 3 4 5 6; do
		pools_conn 203.0.113.1 $((4300 + p)) 198.51.100.2
		a=$(pools_nat_addr rtr 203.0.113.1:$((4300 + p)))
		case "${a}" in
		203.0.113.130|203.0.113.131|203.0.113.132) ;;
		*) atf_fail "connection ${p} translated to '${a}'" ;;
		esac
		chosen="${chosen} ${a}"
	done
	echo "chosen:${chosen}"

	n130=$(pools_count 203.0.113.130 ${chosen})
	n131=$(pools_count 203.0.113.131 ${chosen})
	n132=$(pools_count 203.0.113.132 ${chosen})
	[ ${n131} -ge 1 ] || atf_fail "weight 2 entry never chosen"
	[ ${n132} -ge 2 ] || atf_fail "weight 6 entry chosen ${n132} times"
	[ ${n132} -ge ${n131} ] ||
	    atf_fail "weight 6 entry chosen less often than weight 2 entry"
	[ ${n130} -ge ${n131} ] ||
	    atf_fail "weight 4 entry chosen less often than weight 2 entry"
}

nat_round_robin_weighted_cleanup()
{
	pft_cleanup
}

atf_test_case "nat_source_hash" "cleanup"
nat_source_hash_head()
{
	atf_set descr 'nat-to <table> source-hash with a fixed key is stable'
	atf_set require.user root
	atf_set require.progs python3 scapy
	atf_set timeout 300
}

nat_source_hash_body()
{
	# PF_POOL_SRCHASH on a table: pf_hash with a configured key,
	# tblidx = hash % cnt, pfr_pool_get by index.
	pools_nat44_setup

	key=0x0123456789abcdef0123456789abcdef
	rules_set()
	{
		pft_set_rules rtr \
		    "table <pool> { 203.0.113.130 203.0.113.131 203.0.113.132 }" \
		    "pass" \
		    "pass out on ${epair_wan}a inet proto tcp from 203.0.113.0/25 nat-to <pool> source-hash ${key}"
	}
	rules_set
	atf_check -s exit:0 -o match:"source-hash ${key}" jexec rtr pfctl -sr

	first=""
	for c in 1 2 3 4; do
		pools_conn 203.0.113.${c} 4401 198.51.100.2
		pools_conn 203.0.113.${c} 4402 198.51.100.2
		x=$(pools_nat_addr rtr 203.0.113.${c}:4401)
		y=$(pools_nat_addr rtr 203.0.113.${c}:4402)
		case "${x}" in
		203.0.113.130|203.0.113.131|203.0.113.132) ;;
		*) atf_fail "client ${c} translated to '${x}'" ;;
		esac
		[ "${x}" = "${y}" ] ||
		    atf_fail "client ${c} hashed to ${x} and ${y}"
		first="${first} ${x}"
	done

	# Reload the same ruleset (states and pool counters are reset): the
	# fixed key must reproduce the same mapping.
	rules_set
	second=""
	for c in 1 2 3 4; do
		pools_conn 203.0.113.${c} 4403 198.51.100.2
		second="${second} $(pools_nat_addr rtr 203.0.113.${c}:4403)"
	done
	echo "first:${first} second:${second}"
	[ "${first}" = "${second}" ] ||
	    atf_fail "source-hash mapping changed across reload"
}

nat_source_hash_cleanup()
{
	pft_cleanup
}

atf_test_case "nat_random" "cleanup"
nat_random_head()
{
	atf_set descr 'nat-to random over a prefix and over a table'
	atf_set require.user root
	atf_set require.progs python3 scapy
	atf_set timeout 300
}

nat_random_body()
{
	# PF_POOL_RANDOM: pf_rand_addr for a prefix (init_addr from
	# pf_get_sport), arc4random_uniform(tblidx) + pfr_pool_get for a
	# table.  Loop until two distinct addresses were seen (bounded).
	pools_nat44_setup

	try_random()
	{
		valid="$1"
		port=$2
		seen=""
		i=0
		while [ ${i} -lt 12 ]; do
			i=$((i + 1))
			port=$((port + 1))
			pools_conn 203.0.113.1 ${port} 198.51.100.2
			a=$(pools_nat_addr rtr 203.0.113.1:${port})
			[ -n "${a}" ] && echo "${valid}" | grep -qwF -- "${a}" ||
			    atf_fail "random chose '${a}', not in { ${valid} }"
			[ -z "${seen}" ] && seen=${a}
			[ "${a}" != "${seen}" ] && return 0
		done
		atf_fail "random always chose ${seen}"
	}

	pft_set_rules rtr \
	    "pass" \
	    "pass out on ${epair_wan}a inet proto tcp from 203.0.113.0/25 nat-to 203.0.113.128/30 random"
	try_random "203.0.113.128 203.0.113.129 203.0.113.130 203.0.113.131" 4500

	pft_set_rules rtr \
	    "table <pool> { 203.0.113.140 203.0.113.141 203.0.113.142 }" \
	    "pass" \
	    "pass out on ${epair_wan}a inet proto tcp from 203.0.113.0/25 nat-to <pool> random"
	try_random "203.0.113.140 203.0.113.141 203.0.113.142" 4600
}

nat_random_cleanup()
{
	pft_cleanup
}

atf_test_case "nat66_dynif_linklocal" "cleanup"
nat66_dynif_linklocal_head()
{
	atf_set descr 'nat-to (if) round-robin skips the IPv6 link-local address'
	atf_set require.user root
	atf_set require.progs python3 scapy
	atf_set timeout 300
}

nat66_dynif_linklocal_body()
{
	# PF_ADDR_DYNIFTL pool: pfr_pool_get skips link-local entries of
	# the interface table (pfr_islinklocal) and wraps to index 0.
	pft_init

	epair_lan=$(vnet_mkepair)
	epair_wan=$(vnet_mkepair)

	ifconfig ${epair_lan}a inet6 fd00:66:1::2/64 up no_dad
	route add -6 2001:db8:66::/64 fd00:66:1::1

	vnet_mkjail rtr ${epair_lan}b ${epair_wan}a
	jexec rtr ifconfig ${epair_lan}b inet6 fd00:66:1::1/64 up no_dad
	jexec rtr ifconfig ${epair_wan}a inet6 -ifdisabled auto_linklocal
	jexec rtr ifconfig ${epair_wan}a inet6 2001:db8:66::1/64 up no_dad
	jexec rtr ifconfig ${epair_wan}a inet6 2001:db8:66::3/64 alias no_dad
	jexec rtr sysctl net.inet6.ip6.forwarding=1 > /dev/null
	jexec rtr route add -6 fd00:66:2::/64 fd00:66:1::2

	vnet_mkjail srv ${epair_wan}b
	jexec srv ifconfig ${epair_wan}b inet6 2001:db8:66::2/64 up no_dad
	pools_inetd srv tcp6

	# The pool must really contain a link-local address.
	atf_check -s exit:0 -o match:"inet6 fe80:" \
	    jexec rtr ifconfig ${epair_wan}a inet6
	atf_check -s exit:0 -o ignore ping6 -c 1 fd00:66:1::1

	jexec rtr pfctl -e
	pft_set_rules rtr \
	    "pass" \
	    "pass out on ${epair_wan}a inet6 proto tcp from fd00:66:2::/64 nat-to (${epair_wan}a) round-robin"

	chosen=""
	for p in 1 2 3 4; do
		pools_conn fd00:66:2::1 $((4700 + p)) 2001:db8:66::2
		a=$(pools_nat_addr rtr "fd00:66:2::1[$((4700 + p))]")
		case "${a}" in
		2001:db8:66::1|2001:db8:66::3) ;;
		*) atf_fail "connection ${p} translated to '${a}'" ;;
		esac
		chosen="${chosen} ${a}"
	done
	echo "chosen:${chosen}"
	[ $(pools_count 2001:db8:66::1 ${chosen}) -eq 2 ] ||
	    atf_fail "round-robin did not alternate over the global addresses"
	[ $(pools_count 2001:db8:66::3 ${chosen}) -eq 2 ] ||
	    atf_fail "round-robin did not alternate over the global addresses"
}

nat66_dynif_linklocal_cleanup()
{
	pft_cleanup
}

# ---------------------------------------------------------------------------
# Table administration
# ---------------------------------------------------------------------------

atf_test_case "table_admin" "cleanup"
table_admin_head()
{
	atf_set descr 'Table flags, feedback, weights, replace, expire, zero and kill'
	atf_set require.user root
	atf_set timeout 300
}

table_admin_body()
{
	# pfr_add_addrs/pfr_fill_feedback (A/X/Y feedback), the EPERM error
	# path with pfr_reset_feedback, pfr_set_addrs, pfr_get_astats +
	# pfr_del_addrs (expire), pfr_clr_astats, pfr_clr_tstats/
	# pfr_clstats_ktables, pfr_del_tables/pfr_clr_tables/
	# pfr_setflags_ktables and pfr_detach_table destroying an
	# unreferenced table; network entries use pfr_prepare_network.
	pft_init

	vnet_mkjail alcatraz
	jexec alcatraz pfctl -e

	pft_set_rules alcatraz \
	    "table <p> persist { 192.0.2.0/24 2001:db8::/48 }" \
	    "table <c> const persist { 198.51.100.1 }" \
	    "table <r> { 203.0.113.1 }" \
	    "pass in from <r>"

	atf_check -s exit:0 -e ignore \
	    -o match:"^-pa----[[:space:]]+p$" \
	    -o match:"^cpa----[[:space:]]+c$" \
	    -o match:"^--a-r--[[:space:]]+r$" \
	    jexec alcatraz pfctl -vsT

	# Feedback: new (A), duplicate within the request (X), conflicting
	# negation of an existing network (Y); the existing /24 is silent.
	# OpenBSD's pfctl prints the "!" of the last address on the others
	# too (the table holds them right).
	atf_check -s exit:0 -e match:"1/4 addresses added" \
	    -o match:"^A .198\.51\.100\.7$" \
	    -o match:"^X .198\.51\.100\.7$" \
	    -o match:"^Y !2001:db8::/48$" \
	    -o not-match:"192\.0\.2\.0/24" \
	    jexec alcatraz pfctl -v -t p -T add 192.0.2.0/24 \
	        198.51.100.7 198.51.100.7 "!2001:db8::/48"

	# A const table refuses changes; the feedback is reset on error.
	atf_check -s not-exit:0 -e match:"not permitted" \
	    jexec alcatraz pfctl -v -t c -T add 198.51.100.9
	atf_check -s not-exit:0 -e match:"not permitted" \
	    jexec alcatraz pfctl -v -t c -T delete 198.51.100.1
	atf_check -s exit:0 -o match:"198\.51\.100\.1" \
	    -o not-match:"198\.51\.100\.9" jexec alcatraz pfctl -t c -T show

	# Weight on the command line, kept across a replace.
	atf_check -s exit:0 -e match:"1/1 addresses added" \
	    jexec alcatraz pfctl -t p -T add 192.0.2.77 weight 5
	[ $(pools_tbl_field alcatraz p 192.0.2.77 "Weight:") -eq 5 ] ||
	    atf_fail "weight 5 not reported"

	atf_check -s exit:0 -o ignore \
	    -e match:"1 addresses added" -e match:"2 addresses deleted" \
	    jexec alcatraz pfctl -v -t p -T replace 192.0.2.0/24 \
	        192.0.2.77 weight 5 2001:db8:1::/64
	atf_check -s exit:0 \
	    -o match:"^   192\.0\.2\.0/24$" \
	    -o match:"^   192\.0\.2\.77$" \
	    -o match:"^   2001:db8:1::/64$" \
	    -o not-match:"2001:db8::/48" \
	    -o not-match:"198\.51\.100\.7" \
	    jexec alcatraz pfctl -t p -T show
	[ $(pools_tbl_field alcatraz p 192.0.2.77 "Weight:") -eq 5 ] ||
	    atf_fail "weight lost by replace"

	# Statistics reset: per address, then the whole table.
	atf_check -s exit:0 -e match:"1/1 addresses cleared" \
	    jexec alcatraz pfctl -t p -T zero 192.0.2.77
	atf_check -s exit:0 -e match:"1 table/stats cleared" \
	    jexec alcatraz pfctl -t p -T zero

	# Expire: only the entry older than 2 seconds goes away.
	atf_check -s exit:0 -e match:"1/1 addresses added" \
	    jexec alcatraz pfctl -t e -T add 198.51.100.50
	sleep 3
	atf_check -s exit:0 -e match:"1/1 addresses added" \
	    jexec alcatraz pfctl -t e -T add 198.51.100.51
	atf_check -s exit:0 -e match:"1/1 addresses expired" \
	    jexec alcatraz pfctl -t e -T expire 2
	atf_check -s exit:0 -o match:"198\.51\.100\.51" \
	    -o not-match:"198\.51\.100\.50" jexec alcatraz pfctl -t e -T show

	# Kill a const table and a rule-referenced table.
	atf_check -s exit:0 -e match:"1 table deleted" \
	    jexec alcatraz pfctl -t c -T kill
	atf_check -s exit:0 -e match:"1 table deleted" \
	    jexec alcatraz pfctl -t r -T kill
	atf_check -s exit:0 -e ignore \
	    -o not-match:"[[:space:]]c$" -o not-match:"[[:space:]]r$" \
	    -o match:"[[:space:]]p$" -o match:"[[:space:]]e$" \
	    jexec alcatraz pfctl -vsT

	atf_check -s exit:0 -e match:"tables deleted" \
	    jexec alcatraz pfctl -F Tables
	atf_check -s exit:0 -e ignore -o empty jexec alcatraz pfctl -sT

	# A non-persist table goes away with the last rule using it.
	pft_set_rules alcatraz \
	    "table <q> { 192.0.2.5 }" \
	    "pass in from <q>"
	atf_check -s exit:0 -e ignore -o match:"^--a-r--[[:space:]]+q$" \
	    jexec alcatraz pfctl -vsT
	pft_set_rules noflush alcatraz "pass"
	atf_check -s exit:0 -e ignore -o not-match:"q" jexec alcatraz pfctl -sT
}

table_admin_cleanup()
{
	pft_cleanup
}

atf_test_case "table_anchor" "cleanup"
table_anchor_head()
{
	atf_set descr 'Anchor tables, root fallback, anchor paths and table counters'
	atf_set require.user root
	atf_set timeout 300
}

table_anchor_body()
{
	# pfr_attach_table for an anchor rule (inactive anchor table with a
	# root), pfr_ktable_select_active falling back to the root,
	# pfr_add_tables activating an anchor table, pfr_fix_anchor
	# stripping leading slashes, pfr_get_tstats and pfr_clr_tstats.
	pft_init

	epair=$(vnet_mkepair)
	ifconfig ${epair}a 192.0.2.1/24 up

	vnet_mkjail alcatraz ${epair}b
	jexec alcatraz ifconfig ${epair}b 192.0.2.2/24 up
	jexec alcatraz pfctl -e

	pft_set_rules alcatraz \
	    "table <t> persist { 192.0.2.1 }" \
	    "pass" \
	    "anchor \"a/b\""
	echo "block in quick proto icmp from <t>" | \
	    jexec alcatraz pfctl -a a/b -f -

	# The anchor has no table <t> of its own: the root one blocks.
	atf_check -s not-exit:0 -o ignore -e ignore ping -c 1 -t 1 192.0.2.2

	atf_check -s exit:0 -e ignore \
	    -o match:"^-pa--h-[[:space:]]+t$" \
	    -o match:"In/Block: +\[ Packets: [1-9]" \
	    jexec alcatraz pfctl -vvsT
	atf_check -s exit:0 -e match:"1 table/stats cleared" \
	    jexec alcatraz pfctl -t t -T zero
	# (The match is counted on the anchor's inactive table, as in OpenBSD;
	# the statistics of the packet on the root table.)
	atf_check -s exit:0 -e ignore -o match:"In/Block: +\[ Packets: 0 " \
	    jexec alcatraz pfctl -vvsT

	# An anchor-local table takes precedence once it is active.
	atf_check -s exit:0 -e match:"1/1 addresses added" \
	    jexec alcatraz pfctl -a a/b -t t -T add 192.0.2.99
	atf_check -s exit:0 -o ignore ping -c 1 -t 1 192.0.2.2
	atf_check -s exit:0 -e ignore -o match:"-pa-r--[[:space:]]+t@a/b" \
	    jexec alcatraz pfctl -v -a a/b -sT

	# Leading slashes in the anchor path are stripped by the kernel.
	atf_check -s exit:0 -o match:"192\.0\.2\.99" -o not-match:"192\.0\.2\.1$" \
	    jexec alcatraz pfctl -a //a/b -t t -T show
	atf_check -s exit:0 -e match:"1/1 addresses match" \
	    jexec alcatraz pfctl -a /a/b -t t -T test 192.0.2.99

	# Killing the anchor table falls back to the root table again.
	atf_check -s exit:0 -e match:"1 table deleted" \
	    jexec alcatraz pfctl -a a/b -t t -T kill
	atf_check -s not-exit:0 -o ignore -e ignore ping -c 1 -t 1 192.0.2.2

	atf_check -s exit:0 -e match:"1/1 addresses deleted" \
	    jexec alcatraz pfctl -t t -T delete 192.0.2.1
	atf_check -s exit:0 -o ignore ping -c 1 -t 1 192.0.2.2
}

table_anchor_cleanup()
{
	pft_cleanup
}

# ---------------------------------------------------------------------------
# route-to pools
# ---------------------------------------------------------------------------

atf_test_case "route_rr_sticky" "cleanup"
route_rr_sticky_head()
{
	atf_set descr 'route-to <table> round-robin sticky-address over hosts and a prefix'
	atf_set require.user root
	atf_set require.progs python3 scapy
	atf_set timeout 300
}

route_rr_sticky_body()
{
	# pf_map_addr_sticky (source node hit), pf_insert_src_node,
	# PF_POOL_ROUNDROBIN with pf_poolmask, and pfr_pool_get walking
	# inside a /127 network entry (pfr_prepare_network, rn_match).
	pools_rt_setup

	pft_set_rules router \
	    "set state-policy if-bound" \
	    "table <rt_targets> { ${net_server1_6}::42:0/127 ${net_server2_6}::42:4 }" \
	    "pass in on ${epair_tester}b inet6 proto tcp route-to <rt_targets> round-robin sticky-address keep state"

	pools_rt_conn ${net_clients_6}::1 4801
	pools_rt_conn ${net_clients_6}::1 4802
	pools_rt_conn ${net_clients_6}::2 4803
	pools_rt_conn ${net_clients_6}::3 4804
	pools_rt_conn ${net_clients_6}::2 4805
	pools_rt_conn ${net_clients_6}::4 4806

	for c in "1 4801 ${net_server1_6}::42:0" \
		 "1 4802 ${net_server1_6}::42:0" \
		 "2 4803 ${net_server1_6}::42:1" \
		 "3 4804 ${net_server2_6}::42:4" \
		 "2 4805 ${net_server1_6}::42:1" \
		 "4 4806 ${net_server1_6}::42:0"; do
		set -- ${c}
		t=$(pools_rt_target ${net_clients_6}::$1 $2)
		[ "${t}" = "$3" ] ||
		    atf_fail "client ::$1 port $2 routed to '${t}', expected $3"
	done

	jexec router pfctl -s Sources
	atf_check -s exit:0 -e ignore \
	    -o match:"${net_clients_6}::1 route-to ${net_server1_6}::42:0 \( states 2," \
	    -o match:"${net_clients_6}::2 route-to ${net_server1_6}::42:1 \( states 2," \
	    -o match:"${net_clients_6}::3 route-to ${net_server2_6}::42:4 \( states 1," \
	    jexec router pfctl -s Sources
}

route_rr_sticky_cleanup()
{
	pft_cleanup
}

atf_test_case "route_source_hash" "cleanup"
route_source_hash_head()
{
	atf_set descr 'route-to source-hash with a hex key over a table and a prefix'
	atf_set require.user root
	atf_set require.progs python3 scapy
	atf_set timeout 900	# 24 crafted handshakes
}

route_source_hash_body()
{
	# PF_POOL_SRCHASH: pf_hash with a fixed key, table index selection
	# and, for a prefix, pf_poolmask(naddr, raddr, rmask, hash).
	pools_rt_setup

	key=0x00112233445566778899aabbccddeeff

	run_hash()
	{
		pft_set_rules router \
		    "set state-policy if-bound" \
		    "table <rt_targets> { ${net_server1_6}::42:0 ${net_server1_6}::42:4 ${net_server2_6}::42:0 ${net_server2_6}::42:4 }" \
		    "pass in on ${epair_tester}b inet6 proto tcp route-to $1 source-hash ${key} keep state"
		atf_check -s exit:0 -o match:"source-hash ${key}" \
		    jexec router pfctl -sr
		res=""
		for c in 1 2 3 4; do
			pools_rt_conn ${net_clients_6}::${c} $2
			pools_rt_conn ${net_clients_6}::${c} $(($2 + 1))
			x=$(pools_rt_target ${net_clients_6}::${c} $2)
			y=$(pools_rt_target ${net_clients_6}::${c} $(($2 + 1)))
			[ -n "${x}" ] && echo " $3 " | grep -qF " ${x} " ||
			    atf_fail "client ::${c} routed to '${x}', not in { $3 }"
			[ "${x}" = "${y}" ] ||
			    atf_fail "client ::${c} hashed to ${x} and ${y}"
			res="${res} ${x}"
		done
	}

	# run_hash sets ${res}; it is not run in a subshell so that
	# atf_check/atf_fail inside it end the test case.
	tbl="${net_server1_6}::42:0 ${net_server1_6}::42:4 ${net_server2_6}::42:0 ${net_server2_6}::42:4"
	run_hash "<rt_targets>" 4901 "${tbl}"
	r1="${res}"
	run_hash "<rt_targets>" 4911 "${tbl}"
	r2="${res}"
	echo "table: ${r1} / ${r2}"
	[ -n "${r1}" ] && [ "${r1}" = "${r2}" ] ||
	    atf_fail "table source-hash mapping changed across reload"

	pfx="${net_server1_6}::42:0 ${net_server1_6}::42:1"
	run_hash "${net_server1_6}::42:0/127" 4921 "${pfx}"
	p1="${res}"
	run_hash "${net_server1_6}::42:0/127" 4931 "${pfx}"
	p2="${res}"
	echo "prefix: ${p1} / ${p2}"
	[ -n "${p1}" ] && [ "${p1}" = "${p2}" ] ||
	    atf_fail "prefix source-hash mapping changed across reload"
}

route_source_hash_cleanup()
{
	pft_cleanup
}

# ---------------------------------------------------------------------------
# RFC 6052 address family translation
# ---------------------------------------------------------------------------

atf_test_case "nat64_prefixes" "cleanup"
nat64_prefixes_head()
{
	atf_set descr 'af-to inet with /32 /40 /48 /56 /64 /96 /120 prefixes and an IPv4 rdr prefix'
	atf_set require.user root
	atf_set timeout 300
}

nat64_prefixes_body()
{
	# inet_nat64/inet_nat64_inet for every RFC 6052 prefix length
	# (byte 8 skipped), the /120 extension path of inet_nat64_mask and
	# inet_nat46/inet_nat46_inet for "af-to inet ... to <v4 net>".
	pft_init

	epair_link=$(vnet_mkepair)
	epair=$(vnet_mkepair)

	ifconfig ${epair}a inet6 fd00:64::2/64 up no_dad
	route -6 add default fd00:64::1

	vnet_mkjail rtr ${epair}b ${epair_link}a
	jexec rtr ifconfig ${epair}b inet6 fd00:64::1/64 up no_dad
	jexec rtr ifconfig ${epair_link}a 192.0.2.1/24 up
	jexec rtr sysctl net.inet.ip.forwarding=1 net.inet6.ip6.forwarding=1 \
	    > /dev/null

	vnet_mkjail dst ${epair_link}b
	jexec dst ifconfig ${epair_link}b 192.0.2.2/24 up
	jexec dst route add default 192.0.2.1
	jexec dst pfctl -e
	pft_set_rules dst "pass"

	atf_check -s exit:0 -o ignore ping6 -c 1 fd00:64::1
	atf_check -s exit:0 -o ignore jexec dst ping -c 1 192.0.2.1

	# "prefix destination" pairs, each embedding 192.0.2.2 (c0.00.02.02).
	# More specific prefixes come later: the last matching rule wins.
	cases="
	2001:db8::/32 2001:db8:c000:202::
	2001:db8:100::/40 2001:db8:1c0:2:2::
	2001:db8:122::/48 2001:db8:122:c000:2:200::
	2001:db8:122:300::/56 2001:db8:122:3c0:0:202::
	2001:db8:122:400::/64 2001:db8:122:400:c0:2:200:0
	2001:db8:122:500::/96 2001:db8:122:500::c000:202
	2001:db8:122:600::c000:200/120 2001:db8:122:600::c000:202
	"

	rules=""
	set -- ${cases}
	while [ $# -gt 0 ]; do
		rules="${rules}pass in on ${epair}b inet6 from any to $1 af-to inet from 192.0.2.1\n"
		shift 2
	done
	jexec rtr pfctl -e
	pft_set_rules rtr \
	    "set reassemble yes" \
	    "block" \
	    "pass inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv }" \
	    "${rules}" \
	    "pass in on ${epair}b inet6 from any to 2001:db8:122:700::/64 af-to inet from 192.0.2.1 to 192.0.2.0/24"

	n=0
	set -- ${cases} 2001:db8:122:700::/64 2001:db8:122:700::ab:cd02
	while [ $# -gt 0 ]; do
		pfx=$1
		v6=$2
		shift 2
		n=$((n + 1))
		atf_check -s exit:0 -o ignore ping6 -c 1 ${v6}
		jexec rtr pfctl -ss | grep -F "${v6}" | grep -qF "192.0.2.2" ||
		    atf_fail "no ${v6} -> 192.0.2.2 state for ${pfx}"
	done

	jexec dst pfctl -ss
	cnt=$(jexec dst pfctl -ss | grep -c "192\.0\.2\.1")
	[ ${cnt} -ge ${n} ] ||
	    atf_fail "dst saw ${cnt} translated flows from 192.0.2.1, expected ${n}"
}

nat64_prefixes_cleanup()
{
	pft_cleanup
}

atf_test_case "nat46_prefixes" "cleanup"
nat46_prefixes_head()
{
	atf_set descr 'af-to inet6 with /32 /40 /48 /56 /64 /96 prefixes and the default /96'
	atf_set require.user root
	atf_set timeout 300
}

nat46_prefixes_body()
{
	# NAT46: inet_nat64(AF_INET6)/inet_nat64_inet6 embedding the IPv4
	# destination into the rdr prefix (pf_get_transaddr_af rdr branch)
	# and, without "to", into the /96 of the translated source address.
	pft_init

	epair=$(vnet_mkepair)
	epair_link=$(vnet_mkepair)

	ifconfig ${epair}a 198.51.100.2/24 up
	route add default 198.51.100.1

	vnet_mkjail rtr ${epair}b ${epair_link}a
	jexec rtr ifconfig ${epair}b 198.51.100.1/24 up
	jexec rtr ifconfig ${epair_link}a inet6 fd00:46::1/64 up no_dad
	jexec rtr sysctl net.inet.ip.forwarding=1 net.inet6.ip6.forwarding=1 \
	    > /dev/null

	vnet_mkjail srv ${epair_link}b
	jexec srv ifconfig ${epair_link}b inet6 fd00:46::2/64 up no_dad
	jexec srv route add -6 default fd00:46::1
	jexec srv pfctl -e
	pft_set_rules srv "pass"

	# "to-spec destination" pairs, each embedding 203.0.113.2
	# (cb.00.71.02); "-" is the default (no "to") form.
	cases="
	2001:db8::/32 2001:db8:cb00:7102::
	2001:db8:100::/40 2001:db8:1cb:71:2::
	2001:db8:122::/48 2001:db8:122:cb00:71:200::
	2001:db8:122:300::/56 2001:db8:122:3cb:0:7102::
	2001:db8:122:400::/64 2001:db8:122:400:cb:71:200:0
	2001:db8:122:500::/96 2001:db8:122:500::cb00:7102
	- 2001:db8:122:3ff::cb00:7102
	"

	set -- ${cases}
	while [ $# -gt 0 ]; do
		jexec srv ifconfig ${epair_link}b inet6 $2/128 alias no_dad
		jexec rtr route add -6 $2 fd00:46::2 > /dev/null
		shift 2
	done

	atf_check -s exit:0 -o ignore ping -c 1 198.51.100.1
	atf_check -s exit:0 -o ignore jexec srv ping6 -c 1 fd00:46::1

	jexec rtr pfctl -e
	set -- ${cases}
	while [ $# -gt 0 ]; do
		if [ "$1" = "-" ]; then
			afto="af-to inet6 from 2001:db8:122:3ff::1"
			src=2001:db8:122:3ff::1
		else
			afto="af-to inet6 from fd00:46::1 to $1"
			src=fd00:46::1
		fi
		v6=$2
		shift 2

		pft_set_rules rtr \
		    "set reassemble yes" \
		    "block" \
		    "pass inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv }" \
		    "pass in on ${epair}b inet from any to 203.0.113.2 ${afto}"
		jexec srv pfctl -Fs > /dev/null 2>&1

		atf_check -s exit:0 -o ignore ping -c 1 -t 2 203.0.113.2
		jexec rtr pfctl -ss | grep -F "${v6}" | grep -qF "203.0.113.2" ||
		    atf_fail "no 203.0.113.2 -> ${v6} state for '${afto}'"
		jexec srv pfctl -ss | grep -F "${v6}" | grep -qF "${src}" ||
		    atf_fail "srv did not see ${src} -> ${v6} for '${afto}'"
	done
}

nat46_prefixes_cleanup()
{
	pft_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "nat_least_states"
	atf_add_test_case "nat_round_robin_weighted"
	atf_add_test_case "nat_source_hash"
	atf_add_test_case "nat_random"
	atf_add_test_case "nat66_dynif_linklocal"
	atf_add_test_case "table_admin"
	atf_add_test_case "table_anchor"
	atf_add_test_case "route_rr_sticky"
	atf_add_test_case "route_source_hash"
	atf_add_test_case "nat64_prefixes"
	atf_add_test_case "nat46_prefixes"
}
