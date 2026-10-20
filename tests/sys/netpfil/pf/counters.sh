#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2025 Kajetan Staszkiewicz
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

get_counters()
{
	echo " === rules ==="
	rules=$(mktemp) || exit
	# OpenBSD has no separate NAT ruleset (pfctl -sn): translation rules
	# are filter rules.
	jexec router pfctl -qvvsr | normalize_pfctl_s > $rules
	cat $rules

	echo " === tables ==="
	tables=$(mktemp) || exit 1
	jexec router pfctl -qvvsT > $tables
	cat $tables

	echo " === states ==="
	states=$(mktemp) || exit 1
	jexec router pfctl -qvvss | normalize_pfctl_s > $states
	cat $states

	echo " === nodes ==="
	nodes=$(mktemp) || exit 1
	# "-sS" is ambiguous in OpenBSD's pfctl (Sources, Stlimiters, Srclimiters).
	jexec router pfctl -qvvs Sources | normalize_pfctl_s > $nodes
	cat $nodes
}

# OpenBSD's pfctl -vvsT prints eight counter lines per table, with the
# In/Match and Out/Match counters of match rules, so take twelve lines
# after the table name.  A match rule's table hits are accounted under
# Match, through the state that carries the match rule (OpenBSD's
# pf_counters_inc()); without a state, match rules account no packets.
# The address is looked up in the state key on the wire side of outbound
# states (after NAT) and on the stack side of inbound states (after RDR);
# when the table does not hold it, the packet is accounted as XPass (see
# pfctl(8)).
check_table_counters()
{
	table_name=$1
	table_regexp=$2
	table=$(mktemp) || exit 1
	cat $tables | grep -A12 $table_name | tr '\n' ' ' | awk '{gsub("[\\[\\]]", " ", $0); gsub("[[:blank:]]+"," ",$0); print $0}' > ${table}
	grep -qE "${table_regexp}" ${table} || atf_fail "Bad counters for table ${table_name}"
}

# table_counters <match evaluations> <in block> <in match> <in pass> <in xpass>
#     <out block> <out match> <out pass> <out xpass>; each counter is "packets/bytes".
table_counters()
{
	printf "Evaluations: NoMatch: 0 Match: %s" "$1"
	shift
	for dir in In Out; do
		for op in Block Match Pass XPass; do
			printf " %s/%s: Packets: %s Bytes: %s" $dir $op ${1%/*} ${1#*/}
			shift
		done
	done
}

atf_test_case "match_pass_state" "cleanup"
match_pass_state_head()
{
	atf_set descr 'Counters on match and pass rules'
	atf_set require.user root
}

match_pass_state_body()
{
	setup_router_server_ipv6

	# Thest counters for a statefull firewall. Expose the behaviour of
	# increasing table counters if a table is used multiple times.
	# The table "tbl_in" is used both in match and pass rule. It's Match
	# and Pass counters are both incremented. The tables "tbl_out_match"
	# and "tbl_out_pass" are used only once and have their countes
	# increased only once.
	# Test source node counters for this simple scenario too.
	# (OpenBSD rejects "scrub (random-id)" for inet6; match rules need no
	# action to be recorded on the state.)
	pft_set_rules router \
		"set state-policy if-bound" \
		"table <tbl_in>  { ${net_tester_host_tester} }" \
		"table <tbl_out_pass> { ${net_server_host_server} }" \
		"table <tbl_out_match> { ${net_server_host_server} }" \
		"block" \
		"pass inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv }" \
		"match in  on ${epair_tester}b inet6 proto tcp from <tbl_in>" \
		"pass  in  on ${epair_tester}b inet6 proto tcp from <tbl_in>  keep state (max-src-states 3 source-track rule)" \
		"match out on ${epair_server}a inet6 proto tcp to   <tbl_out_match>" \
		"pass  out on ${epair_server}a inet6 proto tcp to   <tbl_out_pass> keep state"

	# Use a real TCP connection so that it will be properly closed, guaranteeing the amount of packets.
	atf_check -s exit:0 -o match:"This is a test" -x \
		"echo 'This is a test' | nc -w3 ${net_server_host_server} echo"
	# Let FINs pass through.
	sleep 1
	get_counters

	for rule_regexp in \
		"@3 match in on ${epair_tester}b .* Packets: 10 Bytes: 766 States: 1 " \
		"@4 pass in on ${epair_tester}b .* Packets: 10 Bytes: 766 States: 1 " \
		"@5 match out on ${epair_server}a .* Packets: 10 Bytes: 766 States: 1 " \
		"@6 pass out on ${epair_server}a .* Packets: 10 Bytes: 766 States: 1 " \
	; do
		grep -qE "${rule_regexp}" $rules || atf_fail "Rule regexp not found for '${rule_regexp}'"
	done

	# tbl_in: Match from the match rule and Pass from the pass rule, both
	# through the inbound state.
	check_table_counters tbl_in "$(table_counters 2 \
	    0/0 6/455 6/455 0/0  0/0 4/311 4/311 0/0)"
	check_table_counters tbl_out_match "$(table_counters 1 \
	    0/0 4/311 0/0 0/0  0/0 6/455 0/0 0/0)"
	check_table_counters tbl_out_pass "$(table_counters 1 \
	    0/0 0/0 4/311 0/0  0/0 0/0 6/455 0/0)"

	# OpenBSD ends the state's counter line with ", rule N" and then the
	# optional flags (", source-track") or, with -vv, the "id:" line.
	for state_regexp in \
		"${epair_tester}b tcp ${net_server_host_server}.* <- ${net_tester_host_tester}.* 6:4 pkts, 455:311 bytes, rule 4, source-track" \
		"${epair_server}a tcp ${net_server_host_tester}.* -> ${net_server_host_server}.* 6:4 pkts, 455:311 bytes, rule 6[, ]" \
	; do
		grep -qE "${state_regexp}" $states || atf_fail "State not found for '${state_regexp}'"
	done

	# OpenBSD: "addr ( states N, ... ) age ..., P pkts, B bytes, rule N"
	for node_regexp in \
		"${net_tester_host_tester} \( states 1, .* 10 pkts, 766 bytes, rule 4"\
	; do
		grep -qE "${node_regexp}" $nodes || atf_fail "Source node not found for '${node_regexp}'"
	done
}

match_pass_state_cleanup()
{
	pft_cleanup
}

atf_test_case "match_pass_no_state" "cleanup"
match_pass_no_state_head()
{
	atf_set descr 'Counters on match and pass rules without keep state'
	atf_set require.user root
}

match_pass_no_state_body()
{
	setup_router_server_ipv6

	# Test counters for a stateless firewall.
	# The table "tbl_in" is used both in match and pass rule in the inbound
	# direction. The "In/Pass" counter is incremented twice. The table
	# "tbl_inout" matches the same host on inbound and outbound direction.
	# It will also be incremented twice. The tables "tbl_out_match" and
	# "tbl_out_pass" will have their counters increased only once.
	pft_set_rules router \
		"table <tbl_in>        { ${net_tester_host_tester} }" \
		"table <tbl_inout>     { ${net_tester_host_tester} }" \
		"table <tbl_out_match> { ${net_server_host_server} }" \
		"table <tbl_out_pass>  { ${net_server_host_server} }" \
		"block" \
		"pass inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv }" \
		"match in  on ${epair_tester}b inet6 proto tcp from <tbl_inout>" \
		"match in  on ${epair_tester}b inet6 proto tcp from <tbl_in>" \
		"pass  in  on ${epair_tester}b inet6 proto tcp from <tbl_in> no state" \
		"pass  out on ${epair_tester}b inet6 proto tcp to   <tbl_in> no state" \
		"match in  on ${epair_server}a inet6 proto tcp from <tbl_out_match>" \
		"pass  in  on ${epair_server}a inet6 proto tcp from <tbl_out_pass>  no state" \
		"match out on ${epair_server}a inet6 proto tcp from <tbl_inout> no state" \
		"pass  out on ${epair_server}a inet6 proto tcp to   <tbl_out_pass>  no state"

	# Use a real TCP connection so that it will be properly closed, guaranteeing the amount of packets.
	atf_check -s exit:0 -o match:"This is a test" -x \
		"echo 'This is a test' | nc -w3 ${net_server_host_server} echo"
	sleep 1
	get_counters

	# OpenBSD: without a state, a match rule accounts no packets (its
	# actions and counters live on the state of the passing rule); only
	# the passing rule counts, and only its tables account packets.  The
	# tables' evaluation counts are unchanged.
	for rule_regexp in \
		"@3 match in on ${epair_tester}b .* Packets: 0 Bytes: 0 " \
		"@4 match in on ${epair_tester}b .* Packets: 0 Bytes: 0 " \
		"@5 pass in on ${epair_tester}b .* Packets: 6 Bytes: 455 " \
		"@6 pass out on ${epair_tester}b .* Packets: 4 Bytes: 311 " \
		"@7 match in on ${epair_server}a .* Packets: 0 Bytes: 0 " \
		"@8 pass in on ${epair_server}a .* Packets: 4 Bytes: 311 " \
		"@9 match out on ${epair_server}a .* Packets: 0 Bytes: 0 " \
		"@10 pass out on ${epair_server}a .* Packets: 6 Bytes: 455 " \
	; do
		grep -qE "${rule_regexp}" $rules || atf_fail "Rule regexp not found for '${rule_regexp}'"
	done

	check_table_counters tbl_in "$(table_counters 16 \
	    0/0 0/0 6/455 0/0  0/0 0/0 4/311 0/0)"
	check_table_counters tbl_out_match "$(table_counters 4 \
	    0/0 0/0 0/0 0/0  0/0 0/0 0/0 0/0)"
	check_table_counters tbl_out_pass "$(table_counters 10 \
	    0/0 0/0 4/311 0/0  0/0 0/0 6/455 0/0)"
	check_table_counters tbl_inout "$(table_counters 12 \
	    0/0 0/0 0/0 0/0  0/0 0/0 0/0 0/0)"
}

match_pass_no_state_cleanup()
{
	pft_cleanup
}

atf_test_case "match_block" "cleanup"
match_block_head()
{
	atf_set descr 'Counters on match and block rules'
	atf_set require.user root
}

match_block_body()
{
	setup_router_server_ipv6

	# Stateful firewall with a blocking rule. The rule will have its
	# counters increased because it matches and applies correctly.
	# OpenBSD: blocked traffic creates no state, so the "match" rule
	# before the "block" rule accounts no packets and its table only
	# counts evaluations.
	pft_set_rules router \
		"set state-policy if-bound" \
		"table <tbl_in_match> { ${net_server_host_server} }" \
		"table <tbl_in_block> { ${net_server_host_server} }" \
		"block" \
		"pass inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv }" \
		"match  in on ${epair_tester}b inet6 proto tcp to   <tbl_in_match>" \
		"block  in on ${epair_tester}b inet6 proto tcp to   <tbl_in_block>" \
		"pass  out on ${epair_server}a inet6 proto tcp keep state"

	# Wait 3 seconds, that will cause 2 SYNs to be sent out.
	echo 'This is a test' | nc -w3 ${net_server_host_server} echo
	sleep 1
	get_counters

	for rule_regexp in \
		"@3 match in on ${epair_tester}b .* Packets: 0 Bytes: 0 States: 0 " \
		"@4 block drop in on ${epair_tester}b .* Packets: 2 Bytes: 160 States: 0 " \
	; do
		grep -qE "${rule_regexp}" $rules || atf_fail "Rule regexp not found for '${rule_regexp}'"
	done

	check_table_counters tbl_in_match "$(table_counters 2 \
	    0/0 0/0 0/0 0/0  0/0 0/0 0/0 0/0)"
	check_table_counters tbl_in_block "$(table_counters 2 \
	    2/160 0/0 0/0 0/0  0/0 0/0 0/0 0/0)"
}

match_block_cleanup()
{
	pft_cleanup
}

atf_test_case "match_fail" "cleanup"
match_fail_head()
{
	atf_set descr 'Counters on match and failing pass rules'
	atf_set require.user root
}

match_fail_body()
{
	setup_router_server_ipv6

	# Statefull firewall with a failing "pass" rule.
	# When the rule can't apply it will not have its counters increased.
	pft_set_rules router \
		"set state-policy if-bound" \
		"table <tbl_in_match> { ${net_server_host_server} }" \
		"table <tbl_in_fail> { ${net_server_host_server} }" \
		"block" \
		"pass inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv }" \
		"match  in on ${epair_tester}b inet6 proto tcp to <tbl_in_match>" \
		"pass   in on ${epair_tester}b inet6 proto tcp to <tbl_in_fail> keep state (max 1)" \
		"pass  out on ${epair_server}a inet6 proto tcp keep state"

	# The first test will pass and increase the counters for all rules.
	echo 'This is a test' | nc -w3 ${net_server_host_server} echo
	# The second test will go through the "match" rules but fail
	# on the "pass" rule due to 'keep state (max 1)'.
	# Wait 3 seconds, that will cause 2 SYNs to be sent out.
	echo 'This is a test' | nc -w3 ${net_server_host_server} echo
	sleep 1
	get_counters

	for rule_regexp in \
		"@3 match in on ${epair_tester}b .* Packets: 10 Bytes: 766 States: 1 " \
		"@4 pass in on ${epair_tester}b .* Packets: 10 Bytes: 766 States: 1 " \
	; do
		grep -qE "${rule_regexp}" $rules || atf_fail "Rule regexp not found for '${rule_regexp}'"
	done

	# (This used to assign "$table_counters_single=...", which ran a
	# command instead and left the expected counters empty, so the table
	# checks below matched anything.)
	check_table_counters tbl_in_match "$(table_counters 3 \
	    0/0 6/455 0/0 0/0  0/0 4/311 0/0 0/0)"
	check_table_counters tbl_in_fail "$(table_counters 3 \
	    0/0 0/0 6/455 0/0  0/0 0/0 4/311 0/0)"
}

match_fail_cleanup()
{
	pft_cleanup
}

atf_test_case "nat_natonly" "cleanup"
nat_natonly_head()
{
	atf_set descr 'Counters on only a NAT match rule, which creates no state'
	atf_set require.user root
}

nat_natonly_body()
{
	setup_router_server_ipv6

	# The "match ... nat-to" rule matches on pre-NAT addresses.  There is
	# no "pass" rule, and in OpenBSD the implicit default rule passes
	# without state.  A match rule's actions only apply through the state
	# of a passing rule, so nothing is translated, no state is created,
	# every packet is evaluated against the rule, and the rule and its
	# tables account no packets (FreeBSD's "nat" rule created the state).
	pft_set_rules router \
		"set state-policy if-bound" \
		"table <tbl_src_nat> { ${net_tester_host_tester} }" \
		"table <tbl_dst_nat> { ${net_server_host_server} }" \
		"match out on ${epair_server}a inet6 proto tcp from <tbl_src_nat> to <tbl_dst_nat> nat-to ${net_server_host_router}"

	# Use a real TCP connection so that it will be properly closed, guaranteeing the amount of packets.
	atf_check -s exit:0 -o match:"This is a test" -x \
		"echo 'This is a test' | nc -w3 ${net_server_host_server} echo"
	sleep 1
	get_counters

	for rule_regexp in \
		"@0 match out on ${epair_server}a .* Packets: 0 Bytes: 0 States: 0 " \
	; do
		grep -qE "${rule_regexp}" $rules || atf_fail "Rule regexp not found for '${rule_regexp}'"
	done

	# Both tables are evaluated for each of the 6 outbound packets.
	for table_name in tbl_src_nat tbl_dst_nat; do
		check_table_counters ${table_name} "$(table_counters 6 \
		    0/0 0/0 0/0 0/0  0/0 0/0 0/0 0/0)"
	done

	if grep -q " tcp " $states; then
		atf_fail "Unexpected state for a match rule without a pass rule"
	fi
}

nat_natonly_cleanup()
{
	pft_cleanup
}

atf_test_case "nat_nat" "cleanup"
nat_nat_head()
{
	atf_set descr 'Counters on NAT, match and pass rules with keep state'
	atf_set require.user root
}

nat_nat_body()
{
	setup_router_server_ipv6

	# NAT is applied by the first rule (FreeBSD's separate NAT ruleset;
	# in OpenBSD a "match ... nat-to" rule numbered @0 in the one ruleset).
	# The "nat" rule matches on pre-NAT addresses.
	# The "match" rule matches on post-NAT addresses.
	# The "pass" rule matches on post-NAT addresses and creates the state.
	pft_set_rules router \
		"set state-policy if-bound" \
		"table <tbl_src_nat> { ${net_tester_host_tester} }" \
		"table <tbl_dst_nat> { ${net_server_host_server} }" \
		"table <tbl_src_match> { ${net_server_host_router} }" \
		"table <tbl_dst_match> { ${net_server_host_server} }" \
		"table <tbl_src_pass> { ${net_server_host_router} }" \
		"table <tbl_dst_pass> { ${net_server_host_server} }" \
		"match out on ${epair_server}a inet6 proto tcp from <tbl_src_nat> to <tbl_dst_nat> nat-to ${net_server_host_router}" \
		"block" \
		"pass inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv }" \
		"pass  in  on ${epair_tester}b inet6 proto tcp keep state" \
		"match out on ${epair_server}a inet6 proto tcp from <tbl_src_match> to <tbl_dst_match>" \
		"pass  out on ${epair_server}a inet6 proto tcp from <tbl_src_pass>  to <tbl_dst_pass>  keep state"

	# Use a real TCP connection so that it will be properly closed, guaranteeing the amount of packets.
	atf_check -s exit:0 -o match:"This is a test" -x \
		"echo 'This is a test' | nc -w3 ${net_server_host_server} echo"
	sleep 1
	get_counters

	for rule_regexp in \
		"@0 match out on ${epair_server}a .* Packets: 10 Bytes: 766 States: 1 " \
		"@5 match out on ${epair_server}a .* Packets: 10 Bytes: 766 States: 1 " \
		"@6 pass out on ${epair_server}a .* Packets: 10 Bytes: 766 States: 1 " \
	; do
		grep -qE "${rule_regexp}" $rules || atf_fail "Rule regexp not found for '${rule_regexp}'"
	done

	# Outbound state: tables are looked up with the post-NAT source, so
	# the pre-NAT source table counts XPass.
	check_table_counters tbl_src_nat "$(table_counters 1 \
	    0/0 0/0 0/0 4/311  0/0 0/0 0/0 6/455)"
	for table_name in tbl_dst_nat tbl_src_match tbl_dst_match; do
		check_table_counters ${table_name} "$(table_counters 1 \
		    0/0 4/311 0/0 0/0  0/0 6/455 0/0 0/0)"
	done
	for table_name in tbl_src_pass tbl_dst_pass; do
		check_table_counters ${table_name} "$(table_counters 1 \
		    0/0 0/0 4/311 0/0  0/0 0/0 6/455 0/0)"
	done

	for state_regexp in \
		"${epair_server}a tcp ${net_server_host_router}.* -> ${net_server_host_server}.* 6:4 pkts, 455:311 bytes, rule 6[, ]" \
	; do
		grep -qE "${state_regexp}" $states || atf_fail "State not found for '${state_regexp}'"
	done
}

nat_nat_cleanup()
{
	pft_cleanup
}

atf_test_case "nat_match" "cleanup"
nat_match_head()
{
	atf_set descr 'Counters on match with NAT and pass rules'
	atf_set require.user root
}

nat_match_body()
{
	setup_router_server_ipv6

	# NAT is applied on the "match" rule.
	# The "match" rule up to and including the NAT rule match on pre-NAT addresses.
	# The "match" rule after NAT matches on post-NAT addresses.
	# The "pass" rule matches on post-NAT addresses and creates the state.
	pft_set_rules router \
		"set state-policy if-bound" \
		"table <tbl_src_match1> { ${net_tester_host_tester} }" \
		"table <tbl_dst_match1> { ${net_server_host_server} }" \
		"table <tbl_src_match2> { ${net_tester_host_tester} }" \
		"table <tbl_dst_match2> { ${net_server_host_server} }" \
		"table <tbl_src_match3> { ${net_server_host_router} }" \
		"table <tbl_dst_match3> { ${net_server_host_server} }" \
		"table <tbl_src_pass> { ${net_server_host_router} }" \
		"table <tbl_dst_pass> { ${net_server_host_server} }" \
		"block" \
		"pass inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv }" \
		"pass  in  on ${epair_tester}b inet6 proto tcp keep state" \
		"match out on ${epair_server}a inet6 proto tcp from <tbl_src_match1> to <tbl_dst_match1>" \
		"match out on ${epair_server}a inet6 proto tcp from <tbl_src_match2> to <tbl_dst_match2> nat-to ${net_server_host_router}" \
		"match out on ${epair_server}a inet6 proto tcp from <tbl_src_match3> to <tbl_dst_match3>" \
		"pass  out on ${epair_server}a inet6 proto tcp from <tbl_src_pass>  to <tbl_dst_pass>  keep state"

	# Use a real TCP connection so that it will be properly closed, guaranteeing the amount of packets.
	atf_check -s exit:0 -o match:"This is a test" -x \
		"echo 'This is a test' | nc -w3 ${net_server_host_server} echo"
	sleep 1
	get_counters

	for rule_regexp in \
		"@4 match out on ${epair_server}a .* Packets: 10 Bytes: 766 States: 1 " \
		"@5 match out on ${epair_server}a .* Packets: 10 Bytes: 766 States: 1 " \
		"@6 match out on ${epair_server}a .* Packets: 10 Bytes: 766 States: 1 " \
		"@7 pass out on ${epair_server}a .* Packets: 10 Bytes: 766 States: 1 " \
	; do
		grep -qE "${rule_regexp}" $rules || atf_fail "Rule regexp not found for '${rule_regexp}'"
	done

	# Outbound state: tables are looked up with the post-NAT source, so
	# the pre-NAT source tables count XPass.
	for table_name in tbl_src_match1 tbl_src_match2; do
		check_table_counters ${table_name} "$(table_counters 1 \
		    0/0 0/0 0/0 4/311  0/0 0/0 0/0 6/455)"
	done
	for table_name in tbl_dst_match1 tbl_dst_match2 tbl_src_match3 tbl_dst_match3; do
		check_table_counters ${table_name} "$(table_counters 1 \
		    0/0 4/311 0/0 0/0  0/0 6/455 0/0 0/0)"
	done
	for table_name in tbl_src_pass tbl_dst_pass; do
		check_table_counters ${table_name} "$(table_counters 1 \
		    0/0 0/0 4/311 0/0  0/0 0/0 6/455 0/0)"
	done

	for state_regexp in \
		"${epair_server}a tcp ${net_server_host_tester}.* -> ${net_server_host_server}.* 6:4 pkts, 455:311 bytes, rule 7[, ]" \
	; do
		grep -qE "${state_regexp}" $states || atf_fail "State not found for '${state_regexp}'"
	done
}

nat_match_cleanup()
{
	pft_cleanup
}

atf_test_case "nat_pass" "cleanup"
nat_pass_head()
{
	atf_set descr 'Counters on match, and pass with NAT rules'
	atf_set require.user root
}

nat_pass_body()
{
	setup_router_server_ipv6

	# NAT is applied on the "pass" rule which also creates the state.
	# All rules match on pre-NAT addresses.
	pft_set_rules router \
		"set state-policy if-bound" \
		"table <tbl_src_match> { ${net_tester_host_tester} }" \
		"table <tbl_dst_match> { ${net_server_host_server} }" \
		"table <tbl_src_pass> { ${net_tester_host_tester} }" \
		"table <tbl_dst_pass> { ${net_server_host_server} }" \
		"block" \
		"pass inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv }" \
		"pass  in  on ${epair_tester}b inet6 proto tcp keep state" \
		"match out on ${epair_server}a inet6 proto tcp from <tbl_src_match> to <tbl_dst_match>" \
		"pass  out on ${epair_server}a inet6 proto tcp from <tbl_src_pass>  to <tbl_dst_pass>  nat-to ${net_server_host_router} keep state"

	# Use a real TCP connection so that it will be properly closed, guaranteeing the amount of packets.
	atf_check -s exit:0 -o match:"This is a test" -x \
		"echo 'This is a test' | nc -w3 ${net_server_host_server} echo"
	sleep 1
	get_counters

	for rule_regexp in \
		"@4 match out on ${epair_server}a .* Packets: 10 Bytes: 766 States: 1 " \
		"@5 pass out on ${epair_server}a .* Packets: 10 Bytes: 766 States: 1 " \
	; do
		grep -qE "${rule_regexp}" $rules || atf_fail "Rule regexp not found for '${rule_regexp}'"
	done

	# Outbound state: tables are looked up with the post-NAT source, so
	# the pre-NAT source tables count XPass.
	check_table_counters tbl_src_match "$(table_counters 1 \
	    0/0 0/0 0/0 4/311  0/0 0/0 0/0 6/455)"
	check_table_counters tbl_dst_match "$(table_counters 1 \
	    0/0 4/311 0/0 0/0  0/0 6/455 0/0 0/0)"
	check_table_counters tbl_src_pass "$(table_counters 1 \
	    0/0 0/0 0/0 4/311  0/0 0/0 0/0 6/455)"
	check_table_counters tbl_dst_pass "$(table_counters 1 \
	    0/0 0/0 4/311 0/0  0/0 0/0 6/455 0/0)"

	for state_regexp in \
		"${epair_server}a tcp ${net_server_host_router}.* -> ${net_server_host_server}.* 6:4 pkts, 455:311 bytes, rule 5[, ]" \
	; do
		grep -qE "${state_regexp}" $states || atf_fail "State not found for '${state_regexp}'"
	done
}

nat_pass_cleanup()
{
	pft_cleanup
}

atf_test_case "rdr_match" "cleanup"
rdr_match_head()
{
	atf_set descr 'Counters on match with RDR and pass rules'
	atf_set require.user root
}

rdr_match_body()
{
	setup_router_server_ipv6

	# Similar to the nat_match test but for the RDR action.
	# Hopefully we don't need all other tests duplicated for RDR.
	# Send traffic to a non-existing host, RDR it to the server.
	#
	# The "match" rule up to and including the RDR rule match on pre-RDR dst address.
	# The "match" rule after NAT matches on post-RDR dst address.
	# The "pass" rule matches on post-RDR dst address.
	net_server_host_notserver=${net_server_host_server%%::*}::3
	pft_set_rules router \
		"set state-policy if-bound" \
		"table <tbl_src_match1> { ${net_tester_host_tester} }" \
		"table <tbl_dst_match1> { ${net_server_host_notserver} }" \
		"table <tbl_src_match2> { ${net_tester_host_tester} }" \
		"table <tbl_dst_match2> { ${net_server_host_notserver} }" \
		"table <tbl_src_match3> { ${net_tester_host_tester} }" \
		"table <tbl_dst_match3> { ${net_server_host_server} }" \
		"table <tbl_src_pass> { ${net_tester_host_tester} }" \
		"table <tbl_dst_pass> { ${net_server_host_server} }" \
		"block" \
		"pass inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv }" \
		"pass  out on ${epair_server}a inet6 proto tcp keep state" \
		"match  in on ${epair_tester}b inet6 proto tcp from <tbl_src_match1> to <tbl_dst_match1>" \
		"match  in on ${epair_tester}b inet6 proto tcp from <tbl_src_match2> to <tbl_dst_match2> rdr-to ${net_server_host_server}" \
		"match  in on ${epair_tester}b inet6 proto tcp from <tbl_src_match3> to <tbl_dst_match3>" \
		"pass   in on ${epair_tester}b inet6 proto tcp from <tbl_src_pass>  to <tbl_dst_pass>  keep state"

	# Use a real TCP connection so that it will be properly closed, guaranteeing the amount of packets.
	atf_check -s exit:0 -o match:"This is a test" -x \
		"echo 'This is a test' | nc -w3 ${net_server_host_notserver} echo"
	sleep 1
	get_counters

	for rule_regexp in \
		"@4 match in on ${epair_tester}b .* Packets: 10 Bytes: 766 States: 1 " \
		"@5 match in on ${epair_tester}b .* Packets: 10 Bytes: 766 States: 1 " \
		"@6 match in on ${epair_tester}b .* Packets: 10 Bytes: 766 States: 1 " \
		"@7 pass in on ${epair_tester}b .* Packets: 10 Bytes: 766 States: 1 " \
	; do
		grep -qE "${rule_regexp}" $rules || atf_fail "Rule regexp not found for '${rule_regexp}'"
	done

	# Inbound state: tables are looked up with the post-RDR destination,
	# so the pre-RDR destination tables count XPass.
	for table_name in tbl_src_match1 tbl_src_match2 tbl_src_match3 tbl_dst_match3; do
		check_table_counters ${table_name} "$(table_counters 1 \
		    0/0 6/455 0/0 0/0  0/0 4/311 0/0 0/0)"
	done
	for table_name in tbl_dst_match1 tbl_dst_match2; do
		check_table_counters ${table_name} "$(table_counters 1 \
		    0/0 0/0 0/0 6/455  0/0 0/0 0/0 4/311)"
	done
	for table_name in tbl_src_pass tbl_dst_pass; do
		check_table_counters ${table_name} "$(table_counters 1 \
		    0/0 0/0 6/455 0/0  0/0 0/0 4/311 0/0)"
	done

	for state_regexp in \
		"${epair_tester}b tcp ${net_server_host_server}.* 6:4 pkts, 455:311 bytes, rule 7[, ]" \
	; do
		grep -qE "${state_regexp}" $states || atf_fail "State not found for '${state_regexp}'"
	done
}

rdr_match_cleanup()
{
	pft_cleanup
}

atf_test_case "nat64_in" "cleanup"
nat64_in_head()
{
	atf_set descr 'Counters on match and inbound af-to rules'
	atf_set require.user root
}

nat64_in_body()
{
	setup_router_server_nat64

	# OpenBSD binds an if-bound af-to state to the inbound interface
	# (${epair_tester}b), where the IPv4 replies arriving on
	# ${epair_server1}a would not find it, so use floating states.
	pft_set_rules router \
		"table <tbl_src_match> { ${net_tester_6_host_tester} }" \
		"table <tbl_dst_match> { 64:ff9b::${net_server1_4_host_server} }" \
		"table <tbl_src_pass>  { ${net_tester_6_host_tester} }" \
		"table <tbl_dst_pass>  { 64:ff9b::${net_server1_4_host_server} }" \
		"block log" \
		"pass inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv }" \
		"match  in on ${epair_tester}b inet6 proto tcp from <tbl_src_match> to <tbl_dst_match>" \
		"pass   in on ${epair_tester}b inet6 proto tcp from <tbl_src_pass>  to <tbl_dst_pass> \
			af-to inet from (${epair_server1}a) \
			keep state"

	# Use a real TCP connection so that it will be properly closed, guaranteeing the amount of packets.
	atf_check -s exit:0 -o match:"This is a test" -x \
		"echo 'This is a test' | nc -w3 64:ff9b::${net_server1_4_host_server} echo"
	sleep 1
	get_counters

	# Each packet is counted with its size before the af-to translation:
	# 6 IPv6 packets (455 bytes) in and 4 IPv4 replies (231 bytes).
	for rule_regexp in \
		"@3 match in on ${epair_tester}b .* Packets: 10 Bytes: 686 States: 1 " \
		"@4 pass in on ${epair_tester}b .* Packets: 10 Bytes: 686 States: 1 " \
	; do
		grep -qE "${rule_regexp}" $rules || atf_fail "Rule regexp not found for '${rule_regexp}'"
	done

	# OpenBSD binds an af-to state to the inbound interface and keeps one
	# inbound state for both address families: both directions arrive
	# inbound (the replies on ${epair_server1}a), so they are counted in
	# the In direction, and the tables are looked up with the translated
	# (stack side, IPv4) addresses of the state, which the IPv6 tables do
	# not hold: XPass.
	for table_name in tbl_src_match tbl_dst_match tbl_src_pass tbl_dst_pass; do
		check_table_counters ${table_name} "$(table_counters 1 \
		    0/0 0/0 0/0 10/686  0/0 0/0 0/0 0/0)"
	done

	for state_regexp in \
		"all tcp ${net_server_host_tester}.* 10:0 pkts, 686:0 bytes, rule 4[, ]" \
	; do
		grep -qE "${state_regexp}" $states || atf_fail "State not found for '${state_regexp}'"
	done

	echo " === interfaces === "
	echo " === tester === "
	jexec router pfctl -qvvsI -i ${epair_tester}b
	echo " === server === "
	jexec router pfctl -qvvsI -i ${epair_server1}a
	echo " === "
}

nat64_in_cleanup()
{
	pft_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "match_pass_state"
	atf_add_test_case "match_pass_no_state"
	atf_add_test_case "match_block"
	atf_add_test_case "match_fail"
	atf_add_test_case "nat_natonly"
	atf_add_test_case "nat_nat"
	atf_add_test_case "nat_match"
	atf_add_test_case "nat_pass"
	atf_add_test_case "rdr_match"
	atf_add_test_case "nat64_in"
}
