#
# SPDX-License-Identifier: BSD-2-Clause
#
# 5BSD seam tests: per-VNET pf resource quotas.
#
# pf's pools are shared by every VNET, but each VNET counts its own items
# of every pool with a pf limit and is refused at its own limit
# (sys/netpfil/openbsd-pf/pf_quota.c): the host at its own "set limit"
# values, a VNET jail at the host's limit scaled by the host-only sysctl
# net.pf.vnet_limit_pct, shared with its child VNET jails, and all jails
# together at the host's limit scaled by net.pf.vnet_total_pct.  Tag and
# queue ids are per VNET.  A jail therefore cannot use up the host's
# states, fragments or tag ids.
#
# Run exclusively in the host vnet (Makefile); every case saves the host
# limits and the quota sysctls and restores them in cleanup.

. $(atf_get_srcdir)/integration.subr

PFIO=$(atf_get_srcdir)/pfiochelper
FRAGS=$(atf_get_srcdir)/quota_frags.py

# limit_of pool [jail]: print the current hard limit of a pool.
limit_of()
{
	if [ -n "$2" ]; then
		jexec $2 pfctl -sm
	else
		pfctl -sm
	fi | awk -v p="$1" '$1 == p { print $NF }'
}

# quota_sysctl name pool [jail]: net.pf.vnet_<name>.<pool> of a VNET.
quota_sysctl()
{
	if [ -n "$3" ]; then
		jexec $3 sysctl -n net.pf.vnet_$1.$2
	else
		sysctl -n net.pf.vnet_$1.$2
	fi
}

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

# quota_init: pf, per-VNET quotas, saved limits.
quota_init()
{
	pft_init
	quota_pct_set 100
	quota_total_pct_set 200
	limits_save
}

# pinging_jail name: a VNET jail passing everything on its loopback.
pinging_jail()
{
	vnet_mkjail $1
	jexec $1 ifconfig lo0 127.0.0.1/8 up
	# States outlive the test steps (refused pings take a second each).
	pft_set_rules $1 "set timeout { icmp.first 600, icmp.error 600 }" \
	    "pass all"
	jexec $1 pfctl -e
}

quota_cleanup()
{
	# States DIOCADDSTATE added to the host (pfiochelper addstate).
	for _n in 91 92 93; do
		pfctl -k 10.${_n}.0.0/16 > /dev/null 2>&1
	done
	pfctl -a quotas_test -F rules > /dev/null 2>&1
	limits_restore
	quota_pct_restore
	integ_cleanup
}

atf_test_case "jail_state_quota" "cleanup"
jail_state_quota_head()
{
	atf_set descr 'A VNET jail is refused states at its quota; the host still creates states'
	atf_set require.user root
}

jail_state_quota_body()
{
	quota_init
	limits_set "states 1000"
	quota_pct_set 1
	pinging_jail a

	# The jail sees its effective limit, the host keeps its own.
	expect_eq "$(limit_of states a)" "10" "limit_of states a"
	expect_eq "$(quota_sysctl limit states a)" "10" "vnet_limit.states a"
	expect_eq "$(limit_of states)" "1000" "limit_of states"
	expect_eq "$(quota_sysctl limit states)" "1000" "vnet_limit.states"

	# Every ping uses a new ICMP id, so a new state.  At most 10 fit.
	for i in $(seq 1 20); do
		jexec a ping -c 1 -t 1 127.0.0.1 > /dev/null 2>&1
	done
	na=$(state_count a)
	echo "jail a: ${na} states, $(memory_drops a) memory drops," \
	    "$(quota_sysctl refused states a) refused"
	[ "${na}" -ge 1 ] || atf_fail "jail a created no state"
	[ "${na}" -le 10 ] || atf_fail "jail a holds ${na} states, quota 10"
	[ "$(quota_sysctl count states a)" -le 10 ] ||
	    atf_fail "net.pf.vnet_count.states in a exceeds the quota"
	[ "$(memory_drops a)" -gt 0 ] ||
	    atf_fail "jail a has no memory drops at its quota"
	[ "$(quota_sysctl refused states a)" -gt 0 ] ||
	    atf_fail "net.pf.vnet_refused.states in a is 0"

	# DIOCADDSTATE (the pfsync import path) is held to the quota too.
	atf_check -o match:'^DIOCADDSTATE=ENOMEM added=' \
	    jexec a ${PFIO} addstate 20 92

	# The host's budget is its own.
	atf_check -o match:'^DIOCADDSTATE=ok added=50$' ${PFIO} addstate 50 91
	[ "$(quota_sysctl count states)" -ge 50 ] ||
	    atf_fail "net.pf.vnet_count.states on the host is below 50"
}

jail_state_quota_cleanup()
{
	quota_cleanup
}

atf_test_case "host_budget_isolated" "cleanup"
host_budget_isolated_head()
{
	atf_set descr 'A VNET jail at the host-sized quota leaves the host its whole limit'
	atf_set require.user root
}

host_budget_isolated_body()
{
	quota_init
	pinging_jail a

	# The jail's quota is the host's limit (100%): with one shared
	# pool budget, the jail would leave the host nothing.
	own=$(quota_sysctl count states)
	limits_set "states $((own + 10))"
	for i in $(seq 1 30); do
		jexec a ping -c 1 -t 1 127.0.0.1 > /dev/null 2>&1
	done
	na=$(state_count a)
	echo "host: ${own} states; jail a: ${na} states"
	[ "${na}" -ge 10 ] || atf_fail "jail a holds only ${na} states"

	# The host still reaches its own limit, and no further.
	${PFIO} addstate 30 93 > add.out
	cat add.out
	added=$(sed -n 's/^DIOCADDSTATE=ENOMEM added=//p' add.out)
	[ -n "${added}" ] || atf_fail "the host's states limit was not enforced"
	[ "${added}" -ge 10 ] ||
	    atf_fail "the host added ${added} states, its limit leaves 10"
}

host_budget_isolated_cleanup()
{
	quota_cleanup
}

atf_test_case "jail_tag_namespace" "cleanup"
jail_tag_namespace_head()
{
	atf_set descr 'A VNET jail using up its tag ids leaves other VNETs and the host theirs'
	atf_set require.user root
	atf_set timeout 1800
}

jail_tag_namespace_body()
{
	quota_init
	vnet_mkjail a
	vnet_mkjail b

	# 25000 rules with two new tag names each: the 50000 ids of a VNET.
	jot 25000 | awk '{ print "pass all tag t" $1 " tagged u" $1 }' \
	    > tags.conf
	atf_check -s exit:0 -e ignore jexec a pfctl -o none -f ${PWD}/tags.conf
	echo 'pass all tag overflow' > overflow.conf

	# The jail's own name space is full ...
	atf_check -s not-exit:0 -e ignore \
	    jexec a pfctl -a quotas_test -f ${PWD}/overflow.conf

	# ... another VNET's and the host's are not.
	atf_check -s exit:0 -e ignore jexec b pfctl -f ${PWD}/overflow.conf
	atf_check -o match:'tag overflow' jexec b pfctl -sr
	atf_check -s exit:0 -e ignore pfctl -a quotas_test -f ${PWD}/overflow.conf
	atf_check -o match:'tag overflow' pfctl -a quotas_test -sr

	# Flushing the jail's rules gives its ids back.
	atf_check -s exit:0 -e ignore jexec a pfctl -F rules
	atf_check -s exit:0 -e ignore jexec a pfctl -f ${PWD}/overflow.conf
}

jail_tag_namespace_cleanup()
{
	quota_cleanup
}

atf_test_case "jail_fragment_quota" "cleanup"
jail_fragment_quota_head()
{
	atf_set descr 'Fragments held in one VNET do not block reassembly in another'
	atf_set require.user root
}

jail_fragment_quota_body()
{
	quota_init
	integ_require_prog python3

	epb=$(vnet_mkepair)
	epc=$(vnet_mkepair)
	vnet_mkjail a ${epb}a ${epc}a
	vnet_mkjail b ${epb}b
	vnet_mkjail c ${epc}b
	jexec a ifconfig ${epb}a 192.0.2.1/24 up
	jexec b ifconfig ${epb}b 192.0.2.2/24 up
	jexec a ifconfig ${epc}a 198.51.100.1/24 up
	jexec c ifconfig ${epc}b 198.51.100.2/24 up
	for j in b c; do
		pft_set_rules $j "pass all"
		jexec $j pfctl -e
	done

	# With a single pool budget, b's 100 held fragment entries would
	# leave c none.
	limits_set "frags 100"
	expect_eq "$(limit_of frags b)" "100" "limit_of frags b"
	atf_check -s exit:0 -o ignore jexec a ping -c 1 -s 3000 198.51.100.2

	# Resolve b's link-layer address first: raw fragments sent before
	# ARP completes would be dropped.
	atf_check -s exit:0 -o ignore jexec a ping -c 1 192.0.2.2

	# b holds fragments that are never completed, at most its quota;
	# at the quota pf flushes b's own oldest fragments.
	atf_check -s exit:0 -o match:'^sent 300$' \
	    jexec a python3 ${FRAGS} 192.0.2.1 192.0.2.2 300
	nb=$(quota_sysctl count frags b)
	echo "jail b: ${nb} fragment entries," \
	    "$(quota_sysctl refused frags b) refused"
	[ "${nb}" -ge 1 ] || atf_fail "jail b holds no fragment entries"
	[ "${nb}" -le 100 ] || atf_fail "jail b holds ${nb} entries, quota 100"
	[ "$(quota_sysctl refused frags b)" -gt 0 ] ||
	    atf_fail "net.pf.vnet_refused.frags in b is 0"

	# c (as the host would) still reassembles.
	expect_eq "$(quota_sysctl count frags c)" "0" "vnet_count.frags c"
	atf_check -s exit:0 -o ignore jexec a ping -c 1 -s 3000 198.51.100.2
	echo "host: $(quota_sysctl count frags) fragment entries"
}

jail_fragment_quota_cleanup()
{
	quota_cleanup
}

atf_test_case "pct_host_only" "cleanup"
pct_host_only_head()
{
	atf_set descr 'net.pf.vnet_limit_pct is set by the host only, within 1-100'
	atf_set require.user root
}

pct_host_only_body()
{
	quota_init
	vnet_mkjail a

	atf_check -s not-exit:0 -e ignore -o ignore \
	    jexec a sysctl net.pf.vnet_limit_pct=50
	expect_eq "$(sysctl -n net.pf.vnet_limit_pct)" "100" "after jail write"
	expect_eq "$(jexec a sysctl -n net.pf.vnet_limit_pct)" "100" \
	    "jail reads"

	atf_check -s not-exit:0 -e ignore -o ignore sysctl net.pf.vnet_limit_pct=0
	atf_check -s not-exit:0 -e ignore -o ignore sysctl net.pf.vnet_limit_pct=101
	expect_eq "$(sysctl -n net.pf.vnet_limit_pct)" "100" "after bad values"
	atf_check -s not-exit:0 -e ignore -o ignore \
	    jexec a sysctl net.pf.vnet_total_pct=1000
	atf_check -s not-exit:0 -e ignore -o ignore sysctl net.pf.vnet_total_pct=0
	atf_check -s not-exit:0 -e ignore -o ignore \
	    sysctl net.pf.vnet_total_pct=10001
	expect_eq "$(sysctl -n net.pf.vnet_total_pct)" "200" "vnet_total_pct"

	# The host's value applies to every jail at once.
	limits_set "states 4000"
	atf_check -s exit:0 -o ignore sysctl net.pf.vnet_limit_pct=25
	expect_eq "$(limit_of states a)" "1000" "limit_of states a"
	expect_eq "$(limit_of states)" "4000" "limit_of states"
}

pct_host_only_cleanup()
{
	quota_cleanup
}

atf_test_case "jail_restates_quota" "cleanup"
jail_restates_quota_head()
{
	atf_set descr 'A VNET jail restates the host limit or its quota, and cannot change either'
	atf_set require.user root
}

jail_restates_quota_body()
{
	quota_init
	vnet_mkjail a
	limits_set "states 4000"
	quota_pct_set 50

	for v in 4000 2000; do
		printf 'set limit states %s\npass all label "s%s"\n' $v $v \
		    > restate.conf
		atf_check -s exit:0 -e ignore jexec a pfctl -f ${PWD}/restate.conf
		atf_check -o match:"label \"s$v\"" jexec a pfctl -sr
	done
	for v in 1999 2001 4001; do
		printf 'set limit states %s\npass all\n' $v > change.conf
		atf_check -s not-exit:0 -e match:"Cannot set states limit" \
		    jexec a pfctl -f ${PWD}/change.conf
	done
	# A ruleset without "set limit" keeps the quota.
	echo 'pass all label "unstated"' > unstated.conf
	atf_check -s exit:0 -e ignore jexec a pfctl -f ${PWD}/unstated.conf
	expect_eq "$(limit_of states a)" "2000" "limit_of states a"
	expect_eq "$(limit_of states)" "4000" "limit_of states"
}

jail_restates_quota_cleanup()
{
	quota_cleanup
}

# wait_count jail pool value: wait (up to 30 s) until the jail's
# net.pf.vnet_count.<pool> is at most value; removed states are freed by
# the purge task.
wait_count()
{
	for _i in $(seq 1 30); do
		[ "$(quota_sysctl count $2 $1)" -le "$3" ] && return 0
		sleep 1
	done
	atf_fail "net.pf.vnet_count.$2 in $1 stays above $3"
}

atf_test_case "nested_share" "cleanup"
nested_share_head()
{
	atf_set descr 'Child VNET jails share their parent jail'"'"'s quota'
	atf_set require.user root
}

nested_share_body()
{
	quota_init
	limits_set "states 1000"
	quota_pct_set 1
	vnet_mkjail p
	vnet_mkjail q
	jail -m name=p children.max=4 ||
	    atf_skip "nested jails are not available"
	jexec p jail -c name=c1 vnet persist ||
	    atf_skip "nested VNET jails are not available"
	jexec p jail -c name=c2 vnet persist

	# pf runs its purge (which returns flushed states to the pool) only
	# while enabled.
	jexec p jexec c1 pfctl -e >/dev/null 2>&1
	jexec p jexec c2 pfctl -e >/dev/null 2>&1

	# Every jail's quota is 10 states; c1 and c2 count in p's as well.
	atf_check -o match:'^DIOCADDSTATE=ENOMEM added=10$' \
	    jexec p jexec c1 ${PFIO} addstate 20 95
	atf_check -o match:'^DIOCADDSTATE=ENOMEM added=0$' \
	    jexec p jexec c2 ${PFIO} addstate 20 96
	atf_check -o match:'^DIOCADDSTATE=ENOMEM added=0$' \
	    jexec p ${PFIO} addstate 20 97
	expect_eq "$(quota_sysctl count states p)" "10" "vnet_count.states p"
	expect_eq "$(jexec p jexec c1 sysctl -n net.pf.vnet_count.states)" \
	    "10" "vnet_count.states c1"

	# Another jail tree has its own quota.
	atf_check -o match:'^DIOCADDSTATE=ENOMEM added=10$' \
	    jexec q ${PFIO} addstate 20 98

	# c1's states gone, its parent's quota serves c2.
	atf_check -s exit:0 -e ignore -o ignore jexec p jexec c1 pfctl -F states
	wait_count p states 0
	atf_check -o match:'^DIOCADDSTATE=ENOMEM added=10$' \
	    jexec p jexec c2 ${PFIO} addstate 20 96
}

nested_share_cleanup()
{
	jexec p jail -r c1 2>/dev/null
	jexec p jail -r c2 2>/dev/null
	quota_cleanup
}

atf_test_case "jail_total_ceiling" "cleanup"
jail_total_ceiling_head()
{
	atf_set descr 'All VNET jails together are held to net.pf.vnet_total_pct; the host is not'
	atf_set require.user root
}

jail_total_ceiling_body()
{
	quota_init
	limits_set "states 1000"
	quota_pct_set 2
	quota_total_pct_set 5
	vnet_mkjail a
	vnet_mkjail b
	vnet_mkjail c

	# 20 states for each jail, 50 for all of them.
	expect_eq "$(quota_sysctl limit states a)" "20" "vnet_limit.states a"
	expect_eq "$(sysctl -n net.pf.vnet_total_limit.states)" "50" \
	    "vnet_total_limit.states"
	atf_check -o match:'^DIOCADDSTATE=ENOMEM added=20$' \
	    jexec a ${PFIO} addstate 30 95
	atf_check -o match:'^DIOCADDSTATE=ENOMEM added=20$' \
	    jexec b ${PFIO} addstate 30 95
	atf_check -o match:'^DIOCADDSTATE=ENOMEM added=10$' \
	    jexec c ${PFIO} addstate 30 95
	expect_eq "$(sysctl -n net.pf.vnet_total_count.states)" "50" \
	    "vnet_total_count.states"
	[ "$(sysctl -n net.pf.vnet_total_refused.states)" -gt 0 ] ||
	    atf_fail "net.pf.vnet_total_refused.states is 0"

	# The host's own budget is separate from the jails' total.
	atf_check -o match:'^DIOCADDSTATE=ok added=100$' ${PFIO} addstate 100 91

	# Fragments: the jails' total stays within the mbuf clusters the
	# host's own frags limit leaves.
	ncl=$(sysctl -n kern.ipc.nmbclusters)
	hf=$(limit_of frags)
	tf=$(sysctl -n net.pf.vnet_total_limit.frags)
	echo "nmbclusters ${ncl}, host frags ${hf}, jails' frags ${tf}"
	[ "${tf}" -le $((ncl - hf)) ] ||
	    atf_fail "the jails may hold ${tf} fragments, ${ncl} - ${hf} clusters"
}

jail_total_ceiling_cleanup()
{
	quota_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "jail_state_quota"
	atf_add_test_case "host_budget_isolated"
	atf_add_test_case "jail_tag_namespace"
	atf_add_test_case "jail_fragment_quota"
	atf_add_test_case "pct_host_only"
	atf_add_test_case "jail_restates_quota"
	atf_add_test_case "nested_share"
	atf_add_test_case "jail_total_ceiling"
}
