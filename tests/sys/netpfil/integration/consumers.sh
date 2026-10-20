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

# Base-system consumers of OpenBSD PF on 5BSD: the programs that read pf's
# output or its ioctls (periodic, blocklistd, bsnmpd, netstat, tcpdump and
# libpcap, pflogd with newsyslog, truss/kdump through libsysdecode) and the
# capability-limited /dev/pf descriptor that system.Network.PF hands out.
# Everything that changes pf runs inside VNET jails.

. $(atf_get_srcdir)/integration.subr

pfdir=$(atf_get_srcdir)/../pf

# consumers_setup: jail "one" (192.0.2.1, pf enabled) and jail "two"
# (192.0.2.2) on one epair.  Sets ${epair}.
consumers_setup()
{
	pft_init
	epair=$(vnet_mkepair)
	vnet_mkjail one ${epair}a
	vnet_mkjail two ${epair}b
	jexec one ifconfig ${epair}a 192.0.2.1/24 up
	jexec two ifconfig ${epair}b 192.0.2.2/24 up
	jexec one pfctl -e >/dev/null 2>&1
}

# count_pcap file filter: number of packets in a pcap file matching a
# libpcap filter (fails the test if tcpdump rejects the filter).
count_pcap()
{
	_f=$1
	shift
	tcpdump -n -r "${_f}" "$@" > count.out 2> count.err ||
	    atf_fail "tcpdump -r ${_f} '$*' failed: $(cat count.err)"
	wc -l < count.out | tr -d ' '
}

# start_pflogd jail file: run pflogd in the foreground inside a jail
# (no pidfile, so the host's /var/run is untouched); records its pid.
start_pflogd()
{
	jexec $1 pflogd -D -d 5 -i pflog0 -f "$2" > pflogd.log 2>&1 &
	echo $! > pflogd.pid
	# Wait for the log file and its pcap header.
	for _i in 1 2 3 4 5 6 7 8 9 10; do
		[ -s "$2" ] && return 0
		sleep 0.5
	done
	cat pflogd.log
	atf_fail "pflogd did not create $2"
}

# flush_pflogd: SIGALRM makes pflogd flush its buffer (forwarded to the
# unprivileged child by the privileged parent).
flush_pflogd()
{
	kill -ALRM $(cat pflogd.pid)
	sleep 1
}

stop_pflogd()
{
	[ -f pflogd.pid ] || return 0
	_p=$(cat pflogd.pid)
	kill -TERM ${_p} 2>/dev/null
	for _i in 1 2 3 4 5 6 7 8 9 10; do
		kill -0 ${_p} 2>/dev/null || break
		sleep 0.5
	done
	rm -f pflogd.pid
}

# 520.pfdenied writes ${security_status_logdir}/pf.today (/var/log); keep
# the system's files and put them back afterwards.
pfdenied_save()
{
	mkdir -p saved
	for _f in pf.today pf.yesterday; do
		if [ -e /var/log/${_f} ]; then
			mv /var/log/${_f} saved/${_f}
		fi
	done
	touch saved/.done
}

pfdenied_restore()
{
	[ -e saved/.done ] || return 0
	rm -f /var/log/pf.today /var/log/pf.yesterday
	for _f in pf.today pf.yesterday; do
		if [ -e saved/${_f} ]; then
			mv saved/${_f} /var/log/${_f}
		fi
	done
	rm -f saved/.done
}

atf_test_case "periodic_pfdenied" "cleanup"
periodic_pfdenied_head()
{
	atf_set descr 'periodic security 520.pfdenied reports blocked counters from pfctl -vsr, including blocklistd anchors, and -z clears them'
	atf_set require.user root
}

periodic_pfdenied_body()
{
	script=/etc/periodic/security/520.pfdenied
	[ -x ${script} ] || [ -f ${script} ] ||
	    atf_skip "${script} is not installed"
	consumers_setup
	pfdenied_save

	pft_set_rules one \
	    'anchor "blocklistd/*"' \
	    'block in quick proto icmp' \
	    'pass'
	echo 'block in quick proto udp to port 9' |
	    atf_check -s exit:0 jexec one pfctl -a blocklistd/9 -f -

	atf_check -s exit:2 -o ignore jexec two ping -c 3 -t 3 192.0.2.1
	for i in 1 2 3; do
		echo x | jexec two nc -u -w 1 192.0.2.1 9 >/dev/null 2>&1
	done

	# The anchor listing the script walks.
	atf_check -s exit:0 -o match:'blocklistd/9' \
	    jexec one pfctl -a blocklistd -sA

	# An empty previous report makes every blocked rule "new".
	: > /var/log/pf.today
	atf_check -s exit:1 -o save:report1 -e ignore \
	    jexec one env -u PERIODIC sh ${script}
	atf_check -o match:'pf denied packets:' cat report1
	atf_check -o match:'^\+block drop in quick .*proto icmp.*Packets: [1-9]' \
	    cat report1
	atf_check -o match:'^\+block drop in quick .*proto udp .*port = (9|discard).*Packets: [1-9]' \
	    cat report1
	# The pass rule is never reported.
	atf_check -s exit:1 grep -q '^\+pass' report1

	# pfctl -z in the script cleared the counters: nothing new to report.
	atf_check -s exit:0 -o match:'Packets: 0 ' \
	    sh -c "jexec one pfctl -vsr | grep -A1 'proto icmp' | tail -1 | tr -s ' '"
	atf_check -s exit:0 -o empty -e ignore \
	    jexec one env -u PERIODIC sh ${script}

	# The host (test) vnet's pf saw none of it.
	atf_check -s exit:0 -o empty -e ignore pfctl -a blocklistd/9 -sr
}

periodic_pfdenied_cleanup()
{
	pfdenied_restore
	integ_cleanup
}

atf_test_case "blocklistd_helper_enforced" "cleanup"
blocklistd_helper_enforced_head()
{
	atf_set descr 'blocklistd-helper add/rem/flush drive a blocklistd anchor that really blocks and unblocks a TCP peer'
	atf_set require.user root
	atf_set require.progs nc inetd
}

blocklistd_helper_enforced_body()
{
	helper=/usr/libexec/blocklistd-helper
	[ -x ${helper} ] || atf_skip "${helper} is not installed"
	consumers_setup

	pft_set_rules one 'anchor "blocklistd/*"' 'pass'
	jexec one inetd -p ${PWD}/inetd.pid ${pfdir}/echo_inetd.conf
	sleep 1

	atf_check -s exit:0 -o ignore -e ignore \
	    jexec two nc -z -w 2 192.0.2.1 7

	atf_check -s exit:0 -o match:'^OK$' -e ignore \
	    jexec one ${helper} add blocklistd tcp 192.0.2.2 32 7 integ
	atf_check -s exit:0 -o match:'192\.0\.2\.2' \
	    jexec one pfctl -a blocklistd/7 -t port7 -T show
	atf_check -s exit:0 \
	    -o match:'^block drop in quick proto tcp from <port7> to any port = (7|echo)$' \
	    jexec one pfctl -a blocklistd/7 -sr
	atf_check -s not-exit:0 -o ignore -e ignore \
	    jexec two nc -z -w 2 192.0.2.1 7

	# A second add for the same port reuses the rule.
	atf_check -s exit:0 -o match:'^OK$' -e ignore \
	    jexec one ${helper} add blocklistd tcp 192.0.2.3 32 7 integ
	atf_check -s exit:0 -o match:'^1$' \
	    sh -c "jexec one pfctl -a blocklistd/7 -sr | grep -c '<port7>'"

	atf_check -s exit:0 -o match:'^OK$' -e ignore \
	    jexec one ${helper} rem blocklistd tcp 192.0.2.2 32 7 integ
	atf_check -s exit:0 -o not-match:'192\.0\.2\.2$' \
	    jexec one pfctl -a blocklistd/7 -t port7 -T show
	atf_check -s exit:0 -o ignore -e ignore \
	    jexec two nc -z -w 2 192.0.2.1 7

	atf_check -s exit:0 -o match:'^OK$' -e ignore \
	    jexec one ${helper} add blocklistd tcp 192.0.2.2 32 7 integ
	atf_check -s exit:0 -o match:'^OK$' -e ignore \
	    jexec one ${helper} flush blocklistd
	atf_check -s exit:0 -o empty -e ignore \
	    jexec one pfctl -a blocklistd/7 -sr
	# The table is flushed (or gone with its rules).
	atf_check -s ignore -o empty -e ignore \
	    jexec one pfctl -a blocklistd/7 -t port7 -T show
	atf_check -s exit:0 -o ignore -e ignore \
	    jexec two nc -z -w 2 192.0.2.1 7

	# Nothing leaked into the host (test) vnet.
	atf_check -s exit:0 -o empty -e ignore pfctl -a blocklistd/7 -sr
}

blocklistd_helper_enforced_cleanup()
{
	integ_cleanup
}

atf_test_case "bsnmpd_pf_walk" "cleanup"
bsnmpd_pf_walk_head()
{
	atf_set descr 'snmp_pf reports the VNET jail pf: status, counters, limits, timeouts, interfaces, labels, empty pfAltq'
	atf_set require.user root
	atf_set require.progs bsnmpd bsnmpwalk nc
}

bsnmpd_pf_walk_body()
{
	[ -f /usr/lib/snmp_pf.so ] || atf_skip "snmp_pf is not installed"
	consumers_setup

	pft_set_rules one \
	    'block in quick proto udp to port 9 label "integ_block"' \
	    'pass in quick proto icmp label "integ_icmp"' \
	    'pass'
	atf_check -s exit:0 -o ignore jexec two ping -c 2 -t 3 192.0.2.1
	for i in 1 2; do
		echo x | jexec two nc -u -w 1 192.0.2.1 9 >/dev/null 2>&1
	done

	# Start bsnmpd after the traffic so its first refresh sees it.
	jexec one bsnmpd -c ${pfdir}/bsnmpd.conf -p ${PWD}/snmpd.pid
	sleep 1
	walk="bsnmpwalk -s public@192.0.2.1 -i pf_tree.def"
	jexec two ${walk} begemot > walk.out 2>&1 ||
	    atf_fail "bsnmpwalk failed: $(cat walk.out)"

	atf_check -o match:'^pfStatusRunning\.0 = true' cat walk.out
	atf_check -o match:'^pfCounterMatch\.0 = [1-9]' cat walk.out
	atf_check -o match:'^pfStateTableCount\.0 = [1-9]' cat walk.out

	states=$(jexec one pfctl -sm | awk '$1 == "states" { print $NF }')
	atf_check -o match:"^pfLimitsStates\\.0 = ${states}\$" cat walk.out
	est=$(jexec one pfctl -st | awk '$1 == "tcp.established" { print $2 }' |
	    tr -d s)
	atf_check -o match:"^pfTimeoutsTcpEstablished\\.0 = ${est}\$" \
	    cat walk.out

	# The jail's own interface is listed; the peer jail's is not.
	atf_check -o match:"^pfInterfacesIfDescr[.[][0-9]+]? = ${epair}a\$" \
	    cat walk.out
	atf_check -s exit:1 grep -q "^pfInterfacesIfDescr[.[][0-9]*]? = ${epair}b\$" \
	    walk.out

	# Labels, with the counters of the blocked label.
	atf_check -o match:'^pfLabelsLblNumber\.0 = 2$' cat walk.out
	atf_check -o match:'^pfLabelsLblName[.[][0-9]+]? = integ_block$' cat walk.out
	atf_check -o match:'^pfLabelsLblName[.[][0-9]+]? = integ_icmp$' cat walk.out
	idx=$(awk -F'[].[ =]+' '/^pfLabelsLblName.* integ_block$/ { print $2 }' \
	    walk.out)
	atf_check -o match:"^pfLabelsLblPktsIn[.[]${idx}]? = [1-9]" cat walk.out

	# Queues are refused on 5BSD, so the ALTQ group is empty.
	atf_check -o match:'^pfAltqQueueNumber\.0 = 0$' cat walk.out
	atf_check -s exit:1 grep -q '^pfAltqQueueDescr' walk.out
}

bsnmpd_pf_walk_cleanup()
{
	if [ -f snmpd.pid ]; then
		kill $(cat snmpd.pid) 2>/dev/null
	fi
	integ_cleanup
}

atf_test_case "netstat_pfsync_pflow" "cleanup"
netstat_pfsync_pflow_head()
{
	atf_set descr 'netstat -s -p pfsync and -p pflow print every OpenBSD statistic, from the host and from a VNET jail'
	atf_set require.user root
}

netstat_pfsync_pflow_body()
{
	pft_init
	vnet_mkjail one

	for j in "" "jexec one"; do
		$j netstat -s -p pfsync > pfsync.out 2>&1 ||
		    atf_fail "netstat -s -p pfsync failed: $(cat pfsync.out)"
		for f in \
		    '^pfsync:$' \
		    'packets? received \(IPv4\)' \
		    'packets? received \(IPv6\)' \
		    'discarded for bad interface' \
		    'discarded for bad ttl' \
		    'shorter than header' \
		    'discarded for bad version' \
		    'discarded for bad HMAC' \
		    'discarded for bad action' \
		    'discarded for short packet' \
		    'discarded for bad values' \
		    'stale states?' \
		    'failed state lookup/inserts?' \
		    'packets? sent \(IPv4\)' \
		    'packets? sent \(IPv6\)' \
		    'due to mbuf memory error' \
		    'send errors?'; do
			atf_check -o match:"${f}" cat pfsync.out
		done

		$j netstat -s -p pflow > pflow.out 2>&1 ||
		    atf_fail "netstat -s -p pflow failed: $(cat pflow.out)"
		for f in '^pflow:$' 'flows? sent' 'packets? sent' \
		    'send failed due to mbuf memory error' 'send error'; do
			atf_check -o match:"${f}" cat pflow.out
		done
	done

	atf_check -s exit:0 -o match:'"received-inet-packets"' \
	    -o match:'"send-errors"' netstat --libxo json -s -p pfsync
	atf_check -s exit:0 -o match:'"flows"' -o match:'"send-error"' \
	    netstat --libxo json -s -p pflow
	# The statistics are host aggregates and read-only.
	atf_check -s exit:0 -o not-empty sysctl -b net.pfsync.stats
	atf_check -s exit:0 -o not-empty sysctl -b net.pflow.stats
}

netstat_pfsync_pflow_cleanup()
{
	integ_cleanup
}

atf_test_case "pflog_pcap_filters" "cleanup"
pflog_pcap_filters_head()
{
	atf_set descr 'pflogd capture of a VNET jail pflog0 read with tcpdump -r and libpcap pflog filters (action, reason, rulenum, ifname)'
	atf_set require.user root
	atf_set require.progs tcpdump pflogd nc
}

pflog_pcap_filters_body()
{
	pflog_init
	consumers_setup
	atf_check -s exit:0 jexec one ifconfig pflog0 create
	jexec one ifconfig pflog0 up

	# Rule 0 blocks and logs every packet; rule 1 logs the packet that
	# creates the state only.
	pft_set_rules one \
	    "block in log quick on ${epair}a proto udp to port 9" \
	    "pass in log quick on ${epair}a proto icmp" \
	    "pass"
	start_pflogd one ${PWD}/pflog.pcap

	for i in 1 2 3; do
		echo x | jexec two nc -u -w 1 192.0.2.1 9 >/dev/null 2>&1
	done
	atf_check -s exit:0 -o ignore jexec two ping -c 3 -t 4 192.0.2.1
	flush_pflogd
	stop_pflogd

	atf_check_equal 4 $(count_pcap pflog.pcap)
	atf_check_equal 3 $(count_pcap pflog.pcap 'action block')
	atf_check_equal 1 $(count_pcap pflog.pcap 'action pass')
	atf_check_equal 3 $(count_pcap pflog.pcap 'rulenum 0')
	atf_check_equal 1 $(count_pcap pflog.pcap 'rulenum 1')
	atf_check_equal 0 $(count_pcap pflog.pcap 'rulenum 2')
	atf_check_equal 4 $(count_pcap pflog.pcap 'reason match')
	atf_check_equal 4 $(count_pcap pflog.pcap "ifname ${epair}a")
	atf_check_equal 0 $(count_pcap pflog.pcap 'ifname lo0')
	atf_check_equal 3 $(count_pcap pflog.pcap 'action block and udp dst port 9')
	atf_check_equal 1 $(count_pcap pflog.pcap 'inbound and icmp')

	# OpenBSD tcpdump prints the pflog header with -e.
	atf_check -s exit:0 -e ignore \
	    -o match:"rule 0/\\(match\\) block in on ${epair}a: 192\\.0\\.2\\.2\\.[0-9]+ > 192\\.0\\.2\\.1\\.9: udp" \
	    -o match:"rule 1/\\(match\\) pass in on ${epair}a: 192\\.0\\.2\\.2 > 192\\.0\\.2\\.1: icmp: echo request" \
	    tcpdump -n -e -ttt -r pflog.pcap
}

pflog_pcap_filters_cleanup()
{
	stop_pflogd
	integ_cleanup
}

atf_test_case "pflogd_newsyslog" "cleanup"
pflogd_newsyslog_head()
{
	atf_set descr 'newsyslog rotates a pflogd log with the shipped JB flags; pflogd reopens on SIGHUP and both files stay readable'
	atf_set require.user root
	atf_set require.progs tcpdump pflogd newsyslog bzcat nc
	atf_set timeout 120
}

pflogd_newsyslog_body()
{
	conf=/etc/newsyslog.conf.d/pf.conf
	if [ -f ${conf} ]; then
		# The shipped entry: binary file, bzip2, SIGHUP to pflogd.
		atf_check -s exit:0 \
		    -o match:'^/var/log/pflog[[:space:]]+600[[:space:]].*[[:space:]]JB[[:space:]]+/var/run/pflogd\.pid' \
		    cat ${conf}
	fi

	pflog_init
	consumers_setup
	atf_check -s exit:0 jexec one ifconfig pflog0 create
	jexec one ifconfig pflog0 up
	pft_set_rules one \
	    "block in log quick proto udp to port { 9, 10 }" \
	    "pass"
	start_pflogd one ${PWD}/pflog.pcap

	for i in 1 2 3; do
		echo x | jexec two nc -u -w 1 192.0.2.1 9 >/dev/null 2>&1
	done
	flush_pflogd

	# Same flags as the shipped entry; the pid file names our pflogd.
	printf '%s\t600\t3\t1\t*\tJB\t%s\n' ${PWD}/pflog.pcap \
	    ${PWD}/pflogd.pid > newsyslog.conf
	atf_check -s exit:0 -e ignore newsyslog -F -f ${PWD}/newsyslog.conf
	[ -f pflog.pcap.0.bz2 ] || atf_fail "pflog.pcap.0.bz2 was not created"

	for i in 1 2; do
		echo x | jexec two nc -u -w 1 192.0.2.1 10 >/dev/null 2>&1
	done
	flush_pflogd
	stop_pflogd

	bzcat pflog.pcap.0.bz2 > rotated.pcap
	atf_check_equal 3 $(count_pcap rotated.pcap 'udp dst port 9')
	atf_check_equal 0 $(count_pcap rotated.pcap 'udp dst port 10')
	atf_check_equal 2 $(count_pcap pflog.pcap 'udp dst port 10')
	atf_check_equal 0 $(count_pcap pflog.pcap 'udp dst port 9')
}

pflogd_newsyslog_cleanup()
{
	stop_pflogd
	integ_cleanup
}

atf_test_case "sysdecode_pf_ioctls" "cleanup"
sysdecode_pf_ioctls_head()
{
	atf_set descr 'truss and kdump decode OpenBSD pf and 5BSD ether ioctl names through libsysdecode'
	atf_set require.user root
	atf_set require.progs truss ktrace kdump
}

sysdecode_pf_ioctls_body()
{
	pft_init
	vnet_mkjail one

	atf_check -s exit:0 -o ignore -e ignore \
	    jexec one truss -o ${PWD}/truss.out pfctl -si
	atf_check -o match:'ioctl\([0-9]+,DIOCGETSTATUS,' cat truss.out

	atf_check -s exit:0 -o ignore -e ignore \
	    jexec one ktrace -f ${PWD}/ktrace.out pfctl -si
	atf_check -s exit:0 -o match:'CALL +ioctl\(0x[0-9a-f]+,DIOCGETSTATUS,' \
	    kdump -f ktrace.out

	# A ruleset with a 5BSD ether rule ('D' 230..234).
	printf 'ether pass in\npass\n' > ether.conf
	atf_check -s exit:0 -o ignore -e ignore \
	    jexec one ktrace -f ${PWD}/ktrace2.out pfctl -f ${PWD}/ether.conf
	atf_check -s exit:0 -o match:'ioctl\(0x[0-9a-f]+,DIOCADDETHRULE,' \
	    -o match:'ioctl\(0x[0-9a-f]+,DIOCXCOMMIT,' \
	    kdump -f ktrace2.out
	# No pf ('D' group, 0x44) ioctl is left undecoded (kdump prints the
	# number in hex when libsysdecode has no name for it).
	kdump -f ktrace.out > kdump.all 2>/dev/null
	kdump -f ktrace2.out >> kdump.all 2>/dev/null
	atf_check -s exit:1 \
	    grep -Eq 'ioctl\(0x[0-9a-f]+,0x[0-9a-f]*44[0-9a-f]{2},' kdump.all
}

sysdecode_pf_ioctls_cleanup()
{
	integ_cleanup
}

atf_test_case "pf_monitor_descriptor" "cleanup"
pf_monitor_descriptor_head()
{
	atf_set descr 'A /dev/pf descriptor limited like system.Network.PF admits only DIOCGETSTATES and sees the states of its own VNET'
	atf_set require.user root
}

pf_monitor_descriptor_body()
{
	helper=$(atf_get_srcdir)/pf_capfd
	[ -x ${helper} ] || atf_fail "${helper} is missing"
	consumers_setup
	vnet_mkjail empty
	jexec empty pfctl -e >/dev/null 2>&1

	pft_set_rules one 'pass'
	pft_set_rules empty 'pass'
	atf_check -s exit:0 -o ignore jexec two ping -c 1 -t 3 192.0.2.1

	# BSDNetwork narrows its descriptor with cap_rights_limit(READ, FSTAT,
	# IOCTL) and cap_ioctls_limit({ DIOCGETSTATES }); pf_capfd does the
	# same in capability mode and reports what pf answers.
	jexec one ${helper} > one.out 2>&1 || atf_fail "$(cat one.out)"
	atf_check -o match:'^getstates ok [1-9][0-9]*$' cat one.out
	atf_check -o match:'^getstatus ENOTCAPABLE$' cat one.out
	atf_check -o match:'^addrule ENOTCAPABLE$' cat one.out
	atf_check -o match:'^begin ENOTCAPABLE$' cat one.out
	# The ICMP state from the ping is among them.
	atf_check -s exit:0 -o match:'192\.0\.2\.2' jexec one pfctl -ss

	# The same descriptor in another VNET sees that VNET's (empty) table.
	jexec empty ${helper} > empty.out 2>&1 || atf_fail "$(cat empty.out)"
	atf_check -o match:'^getstates ok 0$' cat empty.out

	# The service itself needs an anointed system.network.pf.read client;
	# usr.sbin/BSDNetwork has no command-line client to drive it here.
}

pf_monitor_descriptor_cleanup()
{
	integ_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "periodic_pfdenied"
	atf_add_test_case "blocklistd_helper_enforced"
	atf_add_test_case "bsnmpd_pf_walk"
	atf_add_test_case "netstat_pfsync_pflow"
	atf_add_test_case "pflog_pcap_filters"
	atf_add_test_case "pflogd_newsyslog"
	atf_add_test_case "sysdecode_pf_ioctls"
	atf_add_test_case "pf_monitor_descriptor"
}
