#
# SPDX-License-Identifier: BSD-2-Clause
#
# 5BSD seam tests: /dev/pf and VNET.
#
# Every VNET runs its own OpenBSD pf instance.  /dev/pf binds each open to
# the opener's VNET (sys/netpfil/openbsd-pf/pf_freebsd.c, pf_fbsd_open), so
# rules, states, tables, anchors and interfaces in one VNET jail are not
# visible in another or in the host, and a descriptor keeps addressing the
# VNET it was opened in after it is passed to a process in another VNET.
# devfs ruleset 5 (devfsrules_jail_vnet) exposes /dev/pf to VNET jails;
# ruleset 4 (devfsrules_jail, the jail default) does not.

. $(atf_get_srcdir)/integration.subr

helper=$(atf_get_srcdir)/pf_devhelper.py

host_status()
{
	pfctl -si | awk '/^Status:/ { print $2 }'
}

check_host_status()
{
	after=$(host_status)
	[ "${after}" = "$1" ] ||
	    atf_fail "host pf status changed from '$1' to '${after}'"
}

require_devfs_ruleset()
{
	if [ -z "$(devfs rule -s $1 show 2>/dev/null)" ]; then
		atf_skip "devfs ruleset $1 is not loaded (/etc/rc.d/devfs)"
	fi
}

atf_test_case "isolation" "cleanup"
isolation_head()
{
	atf_set descr 'Rules, anchors, tables, states and interfaces are per VNET'
	atf_set require.user root
}

isolation_body()
{
	pft_init

	epair=$(vnet_mkepair)
	vnet_mkjail a ${epair}a
	vnet_mkjail b ${epair}b
	before=$(host_status)

	jexec a ifconfig lo0 127.0.0.1/8 up
	jexec a ifconfig lo0 inet 203.0.113.77/32 alias
	jexec b ifconfig lo0 127.0.0.1/8 up

	pft_set_rules a \
	    "table <integ_ta> persist { 192.0.2.10, 192.0.2.11 }" \
	    "anchor \"integ_anchor\" {" \
	    "  pass quick proto udp label \"integ_anchor_rule\"" \
	    "}" \
	    "pass all label \"integ_vnet_a\""
	jexec a pfctl -e
	atf_check -s exit:0 -o ignore jexec a ping -c 1 203.0.113.77

	# Present in jail a.
	atf_check -o match:'label "integ_vnet_a"' jexec a pfctl -sr
	atf_check -o match:'integ_anchor' jexec a pfctl -sA
	atf_check -o match:'label "integ_anchor_rule"' \
	    jexec a pfctl -a integ_anchor -sr
	atf_check -o match:'integ_ta' jexec a pfctl -sT
	atf_check -o match:'192\.0\.2\.11' jexec a pfctl -t integ_ta -T show
	atf_check -o match:'203\.0\.113\.77' jexec a pfctl -ss
	atf_check -o match:"^${epair}a\$" jexec a pfctl -sI
	atf_check -o match:'^Status: Enabled' jexec a pfctl -si

	# Absent from jail b and from the host.
	for j in "jexec b" ""; do
		atf_check -o not-match:'integ_vnet_a' $j pfctl -sr
		atf_check -o not-match:'integ_anchor' $j pfctl -sA
		atf_check -o not-match:'integ_ta' $j pfctl -sT
		atf_check -o not-match:'203\.0\.113\.77' $j pfctl -ss
		atf_check -o not-match:"^${epair}a\$" $j pfctl -sI
	done
	atf_check -o match:"^${epair}b\$" jexec b pfctl -sI
	atf_check -o match:'^Status: Disabled' jexec b pfctl -si
	check_host_status "${before}"
}

isolation_cleanup()
{
	integ_cleanup
}

atf_test_case "flush_isolation" "cleanup"
flush_isolation_head()
{
	atf_set descr 'pfctl -F all in one VNET leaves another VNET untouched'
	atf_set require.user root
}

flush_isolation_body()
{
	pft_init

	vnet_mkjail a
	vnet_mkjail b
	pft_set_rules a "pass all label \"keep_a\""
	pft_set_rules b "pass all label \"keep_b\""
	jexec a pfctl -e
	jexec b pfctl -e

	atf_check -s exit:0 -e ignore jexec b pfctl -F all
	jexec b pfctl -d
	atf_check -o match:'label "keep_a"' jexec a pfctl -sr
	atf_check -o match:'^Status: Enabled' jexec a pfctl -si
	atf_check -o not-match:'keep_b' jexec b pfctl -sr
	atf_check -o match:'^Status: Disabled' jexec b pfctl -si
}

flush_isolation_cleanup()
{
	integ_cleanup
}

atf_test_case "teardown_releases" "cleanup"
teardown_releases_head()
{
	atf_set descr 'A VNET recreated under the same jail name starts with empty pf'
	atf_set require.user root
}

teardown_releases_body()
{
	pft_init

	vnet_mkjail a
	pft_set_rules a \
	    "table <gone> persist { 192.0.2.1 }" \
	    "pass all label \"old_vnet\""
	jexec a pfctl -e
	atf_check -s exit:0 jail -r a

	# Same name, new VNET (already listed in created_jails.lst).
	atf_check -s exit:0 jail -c name=a persist vnet
	atf_check -o not-match:'old_vnet' jexec a pfctl -sr
	atf_check -o not-match:'gone' jexec a pfctl -sT
	atf_check -o match:'^Status: Disabled' jexec a pfctl -si
}

teardown_releases_cleanup()
{
	integ_cleanup
}

atf_test_case "fd_passing" "cleanup"
fd_passing_head()
{
	atf_set descr 'A passed /dev/pf descriptor keeps addressing its VNET'
	atf_set require.user root
}

fd_passing_body()
{
	pft_init
	integ_require_prog python3

	vnet_mkjail a
	vnet_mkjail b
	before=$(host_status)
	atf_check -o match:'^Status: Disabled' jexec a pfctl -si
	atf_check -o match:'^Status: Disabled' jexec b pfctl -si

	# b listens; a opens /dev/pf in its VNET and passes the descriptor to
	# b, then exits.  b issues DIOCSTART on the received descriptor.
	jexec b python3 ${helper} recv-start ${PWD}/pf.sock ${PWD}/ready \
	    > recv.out 2>&1 &
	recv_pid=$!
	n=0
	while [ ! -f ready ] && [ $n -lt 100 ]; do
		sleep 0.1
		n=$((n + 1))
	done
	[ -f ready ] || atf_fail "descriptor receiver did not start"
	atf_check -s exit:0 jexec a python3 ${helper} send ${PWD}/pf.sock
	wait ${recv_pid}
	atf_check -o inline:"started\n" cat recv.out

	# pf started in a (the opener's VNET), not in b (the caller's) and not
	# in the host.
	atf_check -o match:'^Status: Enabled' jexec a pfctl -si
	atf_check -o match:'^Status: Disabled' jexec b pfctl -si
	check_host_status "${before}"
}

fd_passing_cleanup()
{
	integ_cleanup
}

atf_test_case "open_limit" "cleanup"
open_limit_head()
{
	atf_set descr '/dev/pf has 1023 clone units; ENXIO when exhausted, reusable after close'
	atf_set require.user root
}

open_limit_body()
{
	pft_init
	integ_require_prog python3

	vnet_mkjail a
	jexec a python3 ${helper} exhaust > exhaust.out
	cat exhaust.out
	# ENXIO is 6.
	atf_check -o match:'^opened [0-9]+ errno 6$' head -1 exhaust.out
	atf_check -o inline:"reopen ok\n" tail -1 exhaust.out
	n=$(awk 'NR == 1 { print $2 }' exhaust.out)
	# Units 1..1023 are shared by all VNETs; a few may be held elsewhere.
	if [ "${n}" -gt 1023 ] || [ "${n}" -lt 900 ]; then
		atf_fail "opened ${n} /dev/pf descriptors, expected 900..1023"
	fi
}

open_limit_cleanup()
{
	integ_cleanup
}

atf_test_case "devfs_ruleset_vnet" "cleanup"
devfs_ruleset_vnet_head()
{
	atf_set descr 'devfs ruleset 5 (devfsrules_jail_vnet) exposes /dev/pf'
	atf_set require.user root
}

devfs_ruleset_vnet_body()
{
	pft_init
	require_devfs_ruleset 5

	root=$(integ_mkjail_devfs vj5 5 vnet)
	atf_check -s exit:0 test -c ${root}/dev/null
	atf_check -s exit:0 test -c ${root}/dev/pf
}

devfs_ruleset_vnet_cleanup()
{
	integ_cleanup
}

atf_test_case "devfs_ruleset_vnet_bpf" "cleanup"
devfs_ruleset_vnet_bpf_head()
{
	atf_set descr 'devfs ruleset 5 exposes bpf (for tcpdump -i pflog0 in a VNET jail)'
	atf_set require.user root
}

devfs_ruleset_vnet_bpf_body()
{
	pft_init
	require_devfs_ruleset 5

	root=$(integ_mkjail_devfs vj5bpf 5 vnet)
	atf_check -s exit:0 test -c ${root}/dev/bpf
}

devfs_ruleset_vnet_bpf_cleanup()
{
	integ_cleanup
}

atf_test_case "devfs_ruleset_jail" "cleanup"
devfs_ruleset_jail_head()
{
	atf_set descr 'devfs ruleset 4 (devfsrules_jail) hides /dev/pf, even from a VNET jail'
	atf_set require.user root
}

devfs_ruleset_jail_body()
{
	pft_init
	require_devfs_ruleset 4

	root=$(integ_mkjail_devfs vj4 4 vnet)
	atf_check -s exit:0 test -c ${root}/dev/null
	atf_check -s not-exit:0 test -e ${root}/dev/pf
}

devfs_ruleset_jail_cleanup()
{
	integ_cleanup
}

atf_test_case "nonvnet_default" "cleanup"
nonvnet_default_head()
{
	atf_set descr 'A non-VNET jail with its own devfs has no /dev/pf by default'
	atf_set require.user root
}

nonvnet_default_body()
{
	pft_init
	require_devfs_ruleset 4

	root=$(integ_mkroot nv)
	# No devfs_ruleset: jail(8) applies its default, ruleset 4.
	atf_check -s exit:0 jail -c name=nv path=${root} persist mount.devfs \
	    ip4=inherit
	echo nv >> created_jails.lst
	atf_check -s exit:0 test -c ${root}/dev/null
	atf_check -s not-exit:0 test -e ${root}/dev/pf
}

nonvnet_default_cleanup()
{
	integ_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "isolation"
	atf_add_test_case "flush_isolation"
	atf_add_test_case "teardown_releases"
	atf_add_test_case "fd_passing"
	atf_add_test_case "open_limit"
	atf_add_test_case "devfs_ruleset_vnet"
	atf_add_test_case "devfs_ruleset_vnet_bpf"
	atf_add_test_case "devfs_ruleset_jail"
	atf_add_test_case "nonvnet_default"
}
