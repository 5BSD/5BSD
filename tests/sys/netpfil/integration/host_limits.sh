#
# SPDX-License-Identifier: BSD-2-Clause
#
# 5BSD seam tests: host-owned pf pool limits.
#
# pf's memory pools (states, src-nodes, frags, tables, table-entries,
# pktdelay-pkts, anchors) are global and shared by every VNET, but their
# limits belong to the host vnet and every VNET is held to its own limit
# in them (per-VNET quotas, quotas.sh).  A VNET jail sees its effective
# limit (the host's, scaled by net.pf.vnet_limit_pct; these cases keep it
# at 100, so the jail sees exactly the host's limits), may restate it
# (pfctl loads every limit with each ruleset), but may not change it:
# DIOCSETLIMIT returns EPERM (pf_quota_setlimit) and pfctl rolls the whole
# ruleset transaction back.  State-pool exhaustion caused by one VNET is
# not visible in any other VNET.
#
# Run exclusively in the host vnet (Makefile); every case saves the host
# limits first and restores them in cleanup (pf/utils.subr).

. $(atf_get_srcdir)/integration.subr

PFIO=$(atf_get_srcdir)/pfiochelper

pools="states src-nodes frags tables table-entries pktdelay-pkts anchors"

# limit_of pool [jail]: print the current hard limit of a pool.
limit_of()
{
	if [ -n "$2" ]; then
		jexec $2 pfctl -sm
	else
		pfctl -sm
	fi | awk -v p="$1" '$1 == p { print $NF }'
}

# restated_limits: "set limit" lines restating every current host limit.
restated_limits()
{
	pfctl -sm | awk '{ print "set limit " $1 " " $NF }'
}

# pfstate_used: pf_state pool items in use, across every VNET (UMA zone
# "pfstate"; the 5BSD pool(9) compatibility layer is built on UMA).
pfstate_used()
{
	vmstat -z | awk -F '[:,]' '$1 == "pfstate" { print $4 + 0 }'
}

# expect_eq actual expected what
expect_eq()
{
	[ "$1" = "$2" ] || atf_fail "$3: got '$1', expected '$2'"
}

memory_drops()
{
	jexec $1 pfctl -si | awk '$1 == "memory" { print $2 }'
}

state_count()
{
	jexec $1 pfctl -si | awk '/current entries/ { print $3; exit }'
}

atf_test_case "jail_sees_host_limits" "cleanup"
jail_sees_host_limits_head()
{
	atf_set descr 'A VNET jail reports exactly the host limits, including changes'
	atf_set require.user root
}

jail_sees_host_limits_body()
{
	pft_init
	quota_pct_set 100
	limits_save
	vnet_mkjail a

	limits_set "states 12345" "src-nodes 2345" "frags 345" \
	    "tables 1234" "table-entries 23456" "anchors 543"
	pfctl -sm > host.sm
	jexec a pfctl -sm > jail.sm
	atf_check -s exit:0 diff -u host.sm jail.sm
	expect_eq "$(limit_of states a)" "12345" "limit_of states a"
	expect_eq "$(limit_of src-nodes a)" "2345" "limit_of src-nodes a"
	expect_eq "$(limit_of frags a)" "345" "limit_of frags a"
	expect_eq "$(limit_of tables a)" "1234" "limit_of tables a"
	expect_eq "$(limit_of table-entries a)" "23456" "limit_of table-entries a"
	expect_eq "$(limit_of anchors a)" "543" "limit_of anchors a"
}

jail_sees_host_limits_cleanup()
{
	limits_restore
	quota_pct_restore
	integ_cleanup
}

atf_test_case "jail_restate_ok" "cleanup"
jail_restate_ok_head()
{
	atf_set descr 'A VNET jail may load a ruleset restating every host limit'
	atf_set require.user root
}

jail_restate_ok_body()
{
	pft_init
	quota_pct_set 100
	limits_save
	vnet_mkjail a

	limits_set "states 20000" "src-nodes 3000"
	restated_limits > restate.conf
	echo 'pass all label "restated"' >> restate.conf
	cat restate.conf

	atf_check -s exit:0 -e ignore jexec a pfctl -f ${PWD}/restate.conf
	atf_check -o match:'label "restated"' jexec a pfctl -sr
	expect_eq "$(limit_of states)" "20000" "limit_of states"
	expect_eq "$(limit_of src-nodes)" "3000" "limit_of src-nodes"
}

jail_restate_ok_cleanup()
{
	limits_restore
	quota_pct_restore
	integ_cleanup
}

# One case per pool: a VNET jail cannot change the pool's limit; the whole
# ruleset is rejected, the jail keeps its old rules and the host keeps its
# limit.
change_rejected_body()
{
	pool=$1
	pft_init
	quota_pct_set 100
	limits_save
	vnet_mkjail a

	pft_set_rules a "pass all label \"before\""
	cur=$(limit_of ${pool})
	[ -n "${cur}" ] || atf_fail "no ${pool} limit in pfctl -sm"
	new=$((cur + 1))

	restated_limits | grep -v " ${pool} " > change.conf
	echo "set limit ${pool} ${new}" >> change.conf
	echo 'pass all label "after"' >> change.conf

	atf_check -s not-exit:0 -e match:"Cannot set ${pool} limit to ${new}" \
	    jexec a pfctl -f ${PWD}/change.conf
	atf_check -o match:'label "before"' jexec a pfctl -sr
	atf_check -o not-match:'label "after"' jexec a pfctl -sr
	expect_eq "$(limit_of ${pool})" "${cur}" "limit_of ${pool}"
	expect_eq "$(limit_of ${pool} a)" "${cur}" "limit_of ${pool} a"
}

for _pool in ${pools}; do
	_tc=change_rejected_$(echo ${_pool} | tr - _)
	eval "
atf_test_case \"${_tc}\" \"cleanup\"
${_tc}_head()
{
	atf_set descr 'A VNET jail cannot change the ${_pool} limit'
	atf_set require.user root
}
${_tc}_body()
{
	change_rejected_body ${_pool}
}
${_tc}_cleanup()
{
	limits_restore
	quota_pct_restore
	integ_cleanup
}
"
done

atf_test_case "unstated_states_limit" "cleanup"
unstated_states_limit_head()
{
	atf_set descr 'A jail ruleset without "set limit states" loads and keeps the host-tuned states limit'
	atf_set require.user root
}

unstated_states_limit_body()
{
	# pfctl loads "states" with its compiled default (PFSTATE_HIWAT,
	# 100000) unless the ruleset sets it.  In a VNET jail the host owns
	# the limit: pfctl keeps the host's value for a limit the ruleset does
	# not set, so a jail ruleset loads after the host tuned the limit.
	pft_init
	quota_pct_set 100
	limits_save
	vnet_mkjail a

	pft_set_rules a "pass all label \"before\""
	limits_set "states 54321"
	echo 'pass all label "unstated"' > unstated.conf
	atf_check -s exit:0 -e ignore jexec a pfctl -f ${PWD}/unstated.conf
	atf_check -o match:'label "unstated"' jexec a pfctl -sr
	expect_eq "$(limit_of states)" "54321" "limit_of states"

	echo 'set limit states 54321' > stated.conf
	echo 'pass all label "stated"' >> stated.conf
	atf_check -s exit:0 -e ignore jexec a pfctl -f ${PWD}/stated.conf
	atf_check -o match:'label "stated"' jexec a pfctl -sr
}

unstated_states_limit_cleanup()
{
	limits_restore
	quota_pct_restore
	integ_cleanup
}

atf_test_case "state_pool_isolated" "cleanup"
state_pool_isolated_head()
{
	atf_set descr 'State-pool exhaustion by one VNET is not visible in another'
	atf_set require.user root
}

state_pool_isolated_body()
{
	pft_init
	quota_pct_set 100
	limits_save

	vnet_mkjail a
	vnet_mkjail b
	for j in a b; do
		jexec $j ifconfig lo0 127.0.0.1/8 up
		# States must outlive the slow steps below (default ~10 s).
		pft_set_rules $j \
		    "set timeout { icmp.first 600, icmp.error 600 }" "pass all"
		jexec $j pfctl -e
	done

	# A small limit the host's own states leave room under.
	lim=$(($(sysctl -n net.pf.vnet_count.states) + 5))
	limits_set "states ${lim}"

	# Every ping uses a new ICMP id, so a new state.  At most ${lim} fit.
	for i in $(seq 1 $((lim + 10))); do
		jexec a ping -c 1 -t 1 127.0.0.1 > /dev/null 2>&1
	done
	na=$(state_count a)
	echo "jail a: ${na} states, $(memory_drops a) memory drops"
	[ "${na}" -le "${lim}" ] ||
	    atf_fail "jail a holds ${na} states, limit allows ${lim}"
	[ "$(memory_drops a)" -gt 0 ] ||
	    atf_fail "jail a has no memory drops after exhausting its limit"

	# b counts its own states: it is not affected by a.
	for i in $(seq 1 3); do
		atf_check -s exit:0 -o ignore jexec b ping -c 1 -t 2 127.0.0.1
	done
	nb=$(state_count b)
	[ "${nb}" -ge 3 ] || atf_fail "jail b holds only ${nb} states"
	expect_eq "$(memory_drops b)" "0" "memory drops in b"
}

state_pool_isolated_cleanup()
{
	limits_restore
	quota_pct_restore
	integ_cleanup
}

atf_test_case "host_lower_below_usage" "cleanup"
host_lower_below_usage_head()
{
	atf_set descr 'The host cannot lower a limit below its own usage, but may below a jail'"'"'s'
	atf_set require.user root
}

host_lower_below_usage_body()
{
	pft_init
	quota_pct_set 100
	limits_save

	vnet_mkjail a
	jexec a ifconfig lo0 127.0.0.1/8 up
	# States must outlive the slow steps below (default ~10 s).
	pft_set_rules a "set timeout { icmp.first 600, icmp.error 600 }" \
	    "pass all"
	jexec a pfctl -e
	for i in $(seq 1 10); do
		jexec a ping -c 1 127.0.0.1 > /dev/null
	done
	[ "$(state_count a)" -ge 10 ] || atf_fail "jail a did not create 10 states"

	# Five host states (DIOCADDSTATE, as pfsync would add them).
	atf_check -o match:'^DIOCADDSTATE=ok added=5$' ${PFIO} addstate 5 94
	own=$(sysctl -n net.pf.vnet_count.states)
	used=$(pfstate_used)
	echo "host: ${own} states; all VNETs: ${used} pfstate items"
	[ "${own}" -ge 5 ] || atf_fail "the host counts ${own} states"

	# Below the host's own usage: refused.
	old=$(limit_of states)
	echo "set limit states $((own - 1))" > lower.conf
	atf_check -s not-exit:0 \
	    -e match:'Current pool size exceeds requested states limit' \
	    pfctl -f ${PWD}/lower.conf
	expect_eq "$(limit_of states)" "${old}" "limit_of states"

	# Below the jail's usage: the jail's states are its own.
	echo "set limit states ${own}" > lower.conf
	atf_check -s exit:0 -e ignore pfctl -f ${PWD}/lower.conf
	expect_eq "$(limit_of states)" "${own}" "limit_of states"
	[ "$(state_count a)" -ge 10 ] || atf_fail "jail a lost states"
}

host_lower_below_usage_cleanup()
{
	pfctl -k 10.94.0.0/16 > /dev/null 2>&1
	limits_restore
	quota_pct_restore
	integ_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "jail_sees_host_limits"
	atf_add_test_case "jail_restate_ok"
	for _pool in ${pools}; do
		atf_add_test_case change_rejected_$(echo ${_pool} | tr - _)
	done
	atf_add_test_case "unstated_states_limit"
	atf_add_test_case "state_pool_isolated"
	atf_add_test_case "host_lower_below_usage"
}
