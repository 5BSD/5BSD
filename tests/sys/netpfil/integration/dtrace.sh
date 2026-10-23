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

# DTrace on the hybrid: the pf SDT provider (dtrace_pf(4)) of the OpenBSD PF
# module, the FreeBSD pfil(9) drop probe, the installed bsdinstruments
# profiles and share/dtrace scripts that use them.  DTrace and pf are
# preloaded on 5BSD (kldload is denied after boot).

. $(atf_get_srcdir)/integration.subr

profiles=/usr/share/bsdinstruments/profiles

dtrace_init()
{
	integ_require_prog dtrace
	kldstat -q -m pf || atf_skip "pf is not loaded (preload pf in loader.conf)"
	dtrace -l -n 'dtrace:::BEGIN' >/dev/null 2>&1 ||
	    atf_skip "DTrace is not available (preload dtraceall)"
}

# The probes listed in the SYNOPSIS of dtrace_pf(4).
documented_probes="
pf:ip:test:entry pf:ip:test:finish
pf:ip:rules:entry
pf:ip:anchor:enter
pf:ip:limiter:decision pf:ip:limiter:pressure pf:ip:limiter:eligible
pf::reason:set
pf:state:state:create pf:state:state:insert pf:state:state:transition
pf:state:state:remove pf:state:state:free
pf:state:purge:run
pf:sctp:multihome:test pf:sctp:multihome:add pf:sctp:multihome:remove
pf:sctp:multihome_scan:entry pf:sctp:multihome_scan:param
pf:sctp:multihome_scan:ipv4 pf:sctp:multihome_scan:ipv6
pf:frag:reassemble:entry pf:frag:reassemble6:entry
pf:nat:transaddr:entry
pf:nat:af_to:translate
pf:ip:route_to:entry pf:ip6:route_to:entry
pf:eth:test_rule:entry pf:eth:test_rule:test pf:eth:test_rule:mismatch
pf:eth:test_rule:match pf:eth:test_rule:final_match
pf:eth:dummynet:submit pf:eth:dummynet:reinject
pf:eth:bridge_to:transmit
pf:eth:hook:link
pf:table:addr:match pf:table:addr:update
pf:rule:jail:match pf:rule:jail:resolve
pf:syncookie:cookie:send pf:syncookie:cookie:validate
pf:log:pflog:packet
pf:pfsync:packet:send pf:pfsync:packet:input
pf:pflow:flow:export
pf:queue:packet:delay
pf:ioctl:ioctl:entry pf:ioctl:ioctl:return
pf:ioctl:xact:begin pf:ioctl:xact:commit pf:ioctl:xact:rollback
sdt:::pf-table-begin sdt:::pf-table-commit sdt:::pf-table-rollback
sdt:::pf-syncookie-active
sdt:::pfsync-queue-pressure
sdt:::pfsync-bulk-start sdt:::pfsync-bulk-status-send
sdt:::pfsync-bulk-retry sdt:::pfsync-bulk-failed
"

atf_test_case "documented_probes" "cleanup"
documented_probes_head()
{
	atf_set descr 'dtrace -l lists every probe in the dtrace_pf(4) SYNOPSIS, and -P pf lists at least as many pf probes'
	atf_set require.user root
}

documented_probes_body()
{
	dtrace_init
	missing=
	n=0
	for p in ${documented_probes}; do
		if ! dtrace -l -n "${p}" > /dev/null 2>&1; then
			missing="${missing} ${p}"
		fi
		case ${p} in pf:*) n=$((n + 1)) ;; esac
	done
	[ -z "${missing}" ] ||
	    atf_fail "documented probes missing from the kernel:${missing}"

	dtrace -l -P pf > pf.list 2>&1 || atf_fail "dtrace -l -P pf failed"
	# Header line plus one line per probe.
	listed=$(($(wc -l < pf.list) - 1))
	[ ${listed} -ge ${n} ] ||
	    atf_fail "dtrace -l -P pf lists ${listed} probes, the manual ${n}"
	# The FreeBSD stack's pfil(9) drop probe is there too.
	atf_check -s exit:0 -o match:'pfil.*drop' dtrace -l -n 'pfil:::drop'
}

documented_probes_cleanup()
{
	integ_cleanup
}

atf_test_case "profiles_compile" "cleanup"
profiles_compile_head()
{
	atf_set descr 'Every installed pf*/pfsync* bsdinstruments profile and the pf share/dtrace scripts compile against the loaded pf.ko'
	atf_set require.user root
	atf_set timeout 600
}

profiles_compile_body()
{
	dtrace_init
	[ -d ${profiles} ] || atf_skip "bsdinstruments profiles are not installed"

	# The profiles 5BSD ships for pf; a missing one is an install bug.
	for p in pf-audit pf-drops pf-frags pf-latency pf-limiter-decisions \
	    pf-nat pf-pfsync pf-queues pf-rules pf-states \
	    pf-table-cookie-events pf-tables pfsync-recovery-events; do
		[ -f ${profiles}/${p}.d ] || atf_fail "${profiles}/${p}.d is missing"
	done

	n=0
	for path in ${profiles}/pf*.d; do
		[ -f "${path}" ] || continue
		# No -Z: every probe a profile names must exist.
		atf_check -s exit:0 -o empty -e empty dtrace -e -s "${path}"
		n=$((n + 1))
	done
	[ ${n} -ge 13 ] || atf_fail "only ${n} pf profiles compiled"

	[ -f /usr/share/dtrace/pf-observe ] ||
	    atf_fail "/usr/share/dtrace/pf-observe is missing"
	atf_check -s exit:0 -o empty -e empty \
	    dtrace -e -s /usr/share/dtrace/pf-observe
}

profiles_compile_cleanup()
{
	integ_cleanup
}

# block_setup: jail "one" (192.0.2.1) with pf blocking and logging inbound
# ICMP, jail "two" (192.0.2.2) as the sender.  Sets ${epair}.
block_setup()
{
	pflog_init
	epair=$(vnet_mkepair)
	vnet_mkjail one ${epair}a
	vnet_mkjail two ${epair}b
	jexec one ifconfig ${epair}a 192.0.2.1/24 up
	jexec two ifconfig ${epair}b 192.0.2.2/24 up
	jexec one ifconfig pflog0 create
	jexec one ifconfig pflog0 up
	jexec one pfctl -e >/dev/null 2>&1
	pft_set_rules one \
	    "block in log quick on ${epair}a inet proto icmp" \
	    "pass"
}

atf_test_case "block_fires_pfil_drop" "cleanup"
block_fires_pfil_drop_head()
{
	atf_set descr 'A pf block in a VNET jail fires pfil:::drop on the jail interface, pf:ip:test:finish with PF_DROP and pf:log:pflog:packet'
	atf_set require.user root
	atf_set timeout 120
}

block_fires_pfil_drop_body()
{
	dtrace_init
	block_setup

	cat > drop.d <<EOF
#pragma D option quiet
pfil:::drop
/stringof(args[2]) == "${epair}a"/
{
	printf("PFIL_DROP %s rv=%d\n", stringof(args[2]), arg1);
}
pf:ip:test:finish
/arg0 == 1 && args[2] != NULL && stringof(args[2]->if_xname) == "${epair}a"/
{
	printf("PF_FINISH_DROP dir=%d\n", arg1);
}
pf:log:pflog:packet
{
	printf("PFLOG_PACKET\n");
}
EOF
	# dtrace -c splits its argument on blanks only: run a script.
	printf 'jexec two ping -c 2 -t 3 192.0.2.1\nexit 0\n' > ping.sh
	atf_check -s exit:0 -o save:dtrace.out -e ignore \
	    dtrace -s drop.d -c "/bin/sh ${PWD}/ping.sh"

	atf_check -o match:"^PFIL_DROP ${epair}a rv=[1-9]" cat dtrace.out
	atf_check -o match:'^PF_FINISH_DROP dir=1$' cat dtrace.out
	atf_check -o match:'^PFLOG_PACKET$' cat dtrace.out
	# Both echo requests were dropped.
	atf_check -o match:'^2$' sh -c "grep -c '^PFIL_DROP' dtrace.out"

	# With the block rule gone nothing is dropped.
	pft_set_rules one "pass"
	atf_check -s exit:0 -o save:dtrace2.out -e ignore \
	    dtrace -s drop.d -c "/bin/sh ${PWD}/ping.sh"
	atf_check -s exit:1 grep -q '^PFIL_DROP' dtrace2.out
}

block_fires_pfil_drop_cleanup()
{
	integ_cleanup
}

atf_test_case "ioctl_probes" "cleanup"
ioctl_probes_head()
{
	atf_set descr 'pfctl in a VNET jail fires pf:ioctl:ioctl:entry/return for DIOCGETSTATUS and the transaction probes on a ruleset load'
	atf_set require.user root
	atf_set timeout 120
}

ioctl_probes_body()
{
	dtrace_init
	pft_init
	vnet_mkjail one

	cat > ioctl.d <<'EOF'
#pragma D option quiet
pf:ioctl:ioctl:entry
/execname == "pfctl"/
{
	printf("ENTRY 0x%x\n", arg0);
}
pf:ioctl:ioctl:return
/execname == "pfctl"/
{
	printf("RETURN 0x%x %d\n", arg0, arg2);
}
pf:ioctl:xact:begin
/execname == "pfctl"/
{
	printf("XACT_BEGIN\n");
}
pf:ioctl:xact:commit
/execname == "pfctl"/
{
	printf("XACT_COMMIT\n");
}
EOF
	# dtrace -c splits its argument on blanks only: run a script.
	printf 'jexec one pfctl -si\necho pass | jexec one pfctl -f -\n' > run.sh
	atf_check -s exit:0 -o save:ioctl.out -e ignore \
	    dtrace -s ioctl.d -c "/bin/sh ${PWD}/run.sh"
	atf_check -o match:'^ENTRY 0x' cat ioctl.out
	atf_check -o match:'^RETURN 0x[0-9a-f]+ 0$' cat ioctl.out
	atf_check -o match:'^XACT_BEGIN$' cat ioctl.out
	atf_check -o match:'^XACT_COMMIT$' cat ioctl.out
	# Every entry has its return.
	atf_check_equal "$(grep -c '^ENTRY' ioctl.out)" \
	    "$(grep -c '^RETURN' ioctl.out)"
}

ioctl_probes_cleanup()
{
	integ_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "documented_probes"
	atf_add_test_case "profiles_compile"
	atf_add_test_case "block_fires_pfil_drop"
	atf_add_test_case "ioctl_probes"
}
