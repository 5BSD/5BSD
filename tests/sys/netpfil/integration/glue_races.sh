#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 The 5BSD Project
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

# Interface names FreeBSD allows and OpenBSD does not, as pf sees them
# Races between pf's glue and the FreeBSD interface and VNET life cycle
# (sys/netpfil/openbsd-pf, contrib/openbsd-pf/sys/net/pf_if.c and
# if_pfsync.c, "5BSD:"): interface index reuse under pfsync, VNET
# teardown with pfsync input, delayed frames and pcb references in
# flight, and pf's interface walks during address and group churn.
# The race cases are smoke tests: they pass by finishing without a panic
# (an INVARIANTS/WITNESS kernel catches more) within their time bound.

. $(atf_get_srcdir)/integration.subr

# ifindex jail ifname: the interface index ifconfig reports.
ifindex()
{
	jexec $1 ifconfig $2 | awk '$1 == "index" {print $2}'
}

atf_test_case "pfsync_syncdev_reuse" "cleanup"
pfsync_syncdev_reuse_head()
{
	atf_set descr 'A sync interface destroyed while pfsync is down is not replaced by a new interface with its index'
	atf_set require.user root
}

pfsync_syncdev_reuse_body()
{
	pft_init
	integ_has_cloner pfsync || atf_skip "ifconfig -C does not list pfsync"
	vnet_mkjail a
	# Created in the jail: destroyed with its VNET.
	old=$(jexec a ifconfig epair create) || atf_fail "cannot create an epair"
	atf_check -s exit:0 -o ignore jexec a ifconfig pfsync0 create
	atf_check -s exit:0 jexec a ifconfig pfsync0 syncdev ${old}
	atf_check -s exit:0 -o match:"syncdev: ${old} " jexec a ifconfig pfsync0
	idx=$(ifindex a ${old})
	[ -n "${idx}" ] || atf_fail "no interface index for ${old}"

	# pfsync0 is down, so no detach hook clears its syncdev.
	atf_check -s exit:0 jexec a ifconfig ${old} destroy
	new=
	for i in 1 2 3 4; do
		n=$(jexec a ifconfig epair create) ||
		    atf_fail "cannot create an epair"
		for h in ${n} ${n%a}b; do
			[ "$(ifindex a ${h})" = "${idx}" ] && new=${h}
		done
		[ -n "${new}" ] && break
	done
	[ -n "${new}" ] || atf_skip "interface index ${idx} was not reused"

	atf_check -s exit:0 -o not-match:"syncdev: ${new} " \
	    jexec a ifconfig pfsync0
	# The new interface can be chosen explicitly.
	atf_check -s exit:0 jexec a ifconfig pfsync0 syncdev ${new}
	atf_check -s exit:0 -o match:"syncdev: ${new} " jexec a ifconfig pfsync0
}

pfsync_syncdev_reuse_cleanup()
{
	integ_cleanup
}

atf_test_case "teardown_busy" "cleanup"
teardown_busy_head()
{
	atf_set descr 'A VNET with pfsync input and delayed frames is torn down promptly while another VNET keeps the pf task queue busy'
	atf_set require.user root
	atf_set timeout 120
}

teardown_busy_body()
{
	pft_init
	integ_has_cloner pfsync || atf_skip "ifconfig -C does not list pfsync"
	for round in 1 2 3; do
		e=$(vnet_mkepair)
		vnet_mkjail victim${round} ${e}a
		vnet_mkjail peer${round} ${e}b
		v="jexec victim${round}"
		p="jexec peer${round}"
		${v} ifconfig ${e}a 192.0.2.1/24 up
		${p} ifconfig ${e}b 192.0.2.2/24 up
		for j in "victim${round} ${e}a" "peer${round} ${e}b"; do
			set -- ${j}
			jexec $1 ifconfig pfsync0 create > /dev/null
			jexec $1 ifconfig pfsync0 syncdev $2 up
			jexec $1 pfctl -e > /dev/null 2>&1
		done
		# The victim holds a frame for a minute; the peer delays every
		# echo request a little and creates a state (and with it pfsync
		# input at the victim) per ping.
		pft_set_rules victim${round} \
		    "pass out quick inet proto icmp icmp-type echoreq set delay 60000" \
		    "pass"
		pft_set_rules peer${round} \
		    "pass out quick inet proto icmp icmp-type echoreq set delay 5" \
		    "pass"
		${v} ping -c 1 -t 1 192.0.2.2 > /dev/null 2>&1
		${p} sh -c 'while :; do ping -c 1 -t 1 -q 192.0.2.1; done' \
		    > /dev/null 2>&1 &
		sleep 2

		start=$(date +%s)
		atf_check -s exit:0 jail -r victim${round}
		took=$(($(date +%s) - start))
		[ ${took} -lt 20 ] ||
		    atf_fail "tearing down victim${round} took ${took}s"
		# The other VNET's pf goes on.
		atf_check -s exit:0 -o match:"Status: Enabled" \
		    ${p} pfctl -s info
		atf_check -s exit:0 jail -r peer${round}
		# Both ends are back in the host VNET.
		ifconfig ${e}a destroy
	done
}

teardown_busy_cleanup()
{
	integ_cleanup
}

atf_test_case "addr_group_churn" "cleanup"
addr_group_churn_head()
{
	atf_set descr 'pf interface walks (dynamic addresses, set loginterface on a group, interface queries) during address and group churn'
	atf_set require.user root
	atf_set timeout 120
}

addr_group_churn_body()
{
	pft_init
	e=$(vnet_mkepair)
	vnet_mkjail a ${e}a
	a="jexec a"
	${a} ifconfig ${e}a 192.0.2.1/24 up
	${a} ifconfig ${e}a group churn
	${a} pfctl -e > /dev/null 2>&1
	pft_set_rules a \
	    "set loginterface churn" \
	    "pass in on ${e}a from (${e}a:network) to (${e}a)" \
	    "pass out to (churn)" \
	    "pass"

	# Addresses and group membership come and go...
	${a} sh -c "i=0; while :; do
		i=\$(((i + 1) % 200 + 10))
		ifconfig ${e}a inet 198.51.100.\${i}/32 alias
		ifconfig ${e}a inet6 2001:db8::\${i}/128 alias no_dad
		ifconfig ${e}a -group churn
		ifconfig ${e}a group churn
		ifconfig ${e}a inet 198.51.100.\${i}/32 -alias
		ifconfig ${e}a inet6 2001:db8::\${i}/128 -alias
	done" > /dev/null 2>&1 &
	# ...while pf reads them: status (the loginterface group), interface
	# queries by group, and reloads (dynamic address setup, flag commit).
	end=$(($(date +%s) + 15))
	while [ $(date +%s) -lt ${end} ]; do
		${a} pfctl -s info > /dev/null 2>&1
		${a} pfctl -sI -i churn -vv > /dev/null 2>&1
		${a} pfctl -s Tables > /dev/null 2>&1
		pft_set_rules a \
		    "set loginterface churn" \
		    "set skip on churn" \
		    "pass in on ${e}a from (${e}a:network) to (${e}a)" \
		    "pass out to (churn)" \
		    "pass"
	done
	atf_check -s exit:0 -o match:"Status: Enabled" ${a} pfctl -s info
}

addr_group_churn_cleanup()
{
	integ_cleanup
}

atf_test_case "new_group_dynaddr" "cleanup"
new_group_dynaddr_head()
{
	atf_set descr 'Dynamic address setup walks the groups of an interface that is joining new groups'
	atf_set require.user root
	atf_set timeout 300
}

new_group_dynaddr_body()
{
	pft_init
	e=$(vnet_mkepair)
	vnet_mkjail a ${e}a
	a="jexec a"
	${a} ifconfig ${e}a 192.0.2.1/24 up
	${a} pfctl -e > /dev/null 2>&1

	# Every round makes a new group: one is on the interface's group
	# list before pf's attach handler has given it a kif.
	${a} sh -c "i=0; while :; do
		i=\$(((i + 1) % 1000))
		ifconfig ${e}a group ng\${i}x
		ifconfig ${e}a -group ng\${i}x
	done" > /dev/null 2>&1 &
	# Each load sets up the dynamic addresses, which walks those groups.
	end=$(($(date +%s) + 60))
	while [ $(date +%s) -lt ${end} ]; do
		pft_set_rules a \
		    "pass in on ${e}a from (${e}a:network) to (${e}a)" \
		    "pass out from (${e}a:0) to (${e}a:broadcast)" \
		    "pass"
	done
	atf_check -s exit:0 -o match:"Status: Enabled" ${a} pfctl -s info
}

new_group_dynaddr_cleanup()
{
	integ_cleanup
}

atf_test_case "teardown_pcb" "cleanup"
teardown_pcb_head()
{
	atf_set descr 'A VNET whose pf states hold socket references is torn down with the connections open'
	atf_set require.user root
	atf_set timeout 300
}

teardown_pcb_body()
{
	pft_init
	integ_require_prog nc
	for round in 1 2 3 4 5; do
		vnet_mkjail pcb${round}
		j="jexec pcb${round}"
		${j} ifconfig lo0 127.0.0.1/8 up
		${j} pfctl -e > /dev/null 2>&1
		pft_set_rules pcb${round} "pass"
		for port in 4001 4002 4003; do
			${j} sh -c "nc -l 127.0.0.1 ${port} > /dev/null &
			    sleep 0.2; (while :; do echo x; sleep 0.1; done) |
			    nc 127.0.0.1 ${port}" > /dev/null 2>&1 &
			${j} sh -c "nc -u -l 127.0.0.1 ${port} > /dev/null &
			    sleep 0.2; (while :; do echo x; sleep 0.1; done) |
			    nc -u 127.0.0.1 ${port}" > /dev/null 2>&1 &
		done
		# Wait for a connection: the listeners start in the background.
		n=0
		until ${j} pfctl -ss 2>/dev/null | grep -q "tcp.*127.0.0.1"; do
			n=$((n + 1))
			[ ${n} -le 50 ] || break
			sleep 0.2
		done
		atf_check -s exit:0 -o match:"tcp.*127.0.0.1" ${j} pfctl -ss
		atf_check -s exit:0 jail -r pcb${round}
	done
}

teardown_pcb_cleanup()
{
	integ_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "pfsync_syncdev_reuse"
	atf_add_test_case "teardown_busy"
	atf_add_test_case "addr_group_churn"
	atf_add_test_case "new_group_dynaddr"
	atf_add_test_case "teardown_pcb"
}
