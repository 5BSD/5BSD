#
# SPDX-License-Identifier: BSD-2-Clause
#
# Run the imported OpenBSD PF regress suites (contrib/openbsd-pf) unchanged
# through OpenBSD's bsd.regress.mk.  Each upstream target is reported in
# REGRESS_LOG; the ATF case fails when any target fails and lists them.
#
# Local suites run on this machine.  Multi-host suites (pf_forward,
# pf_fragment, pf_state, pf_divert) need the two-guest topology described
# in tools/test/pf-parity/openbsd-regress/README and are skipped unless the
# Kyua variable openbsd_regress_topology is set; they are normally driven
# from the OpenBSD helper guest by tools/test/pf-parity/openbsd-regress.
#

srctree()
{
	echo "$(atf_get_srcdir)/srctree/contrib/openbsd-pf"
}

run_suite()
{
	local dir=$1; shift
	local corpus work log

	corpus=$(srctree)
	[ -d "${corpus}/regress/${dir}" ] || atf_skip "corpus not installed"
	kldstat -q -m pf || atf_skip "pf is not loaded"
	# Upstream Makefiles locate helpers through relative paths, so keep the
	# upstream layout (regress/... next to sbin/ and sys/).
	work=$(pwd)/src
	mkdir -p "${work}"
	cp -R "${corpus}/regress" "${work}/"
	log=$(pwd)/regress.log
	: > "${log}"
	(cd "${work}/regress/${dir}" && \
	    env MAKESYSPATH="$(atf_get_srcdir)/mk:/usr/share/mk" \
	    BSDSRCDIR="${work}" make REGRESS_LOG="${log}" REGRESS_FAIL_EARLY=no \
	    "$@" regress) > out 2>&1 || true
	cat out
	if ! grep -q . "${log}"; then
		grep -q SKIPPED out && atf_skip "upstream suite skipped: $(grep -B2 SKIPPED out | head -2 | tr '\n' ' ')"
		atf_fail "no per-target results"
	fi
	if grep -q '^FAIL' "${log}"; then
		atf_fail "$(grep -c '^FAIL' "${log}") failed: $(grep '^FAIL' "${log}" | sed 's,.*/,,' | tr '\n' ' ')"
	fi
}

local_case()
{
	local name=$1 dir=$2 descr=$3
	eval "${name}_head() { atf_set descr '${descr}'; atf_set require.user root; }"
	eval "${name}_body() { run_suite ${dir}; }"
	atf_add_test_case "${name}"
}

topology_case()
{
	local name=$1 dir=$2 descr=$3
	eval "${name}_head() { atf_set descr '${descr}'; atf_set require.user root; }"
	eval "${name}_body() {
		atf_config_has openbsd_regress_topology || \
		    atf_skip 'needs the two-guest topology (tools/test/pf-parity/openbsd-regress)'
		run_suite ${dir} \$(atf_config_get openbsd_regress_topology)
	}"
	atf_add_test_case "${name}"
}

atf_init_test_cases()
{
	local_case pfctl sbin/pfctl "pfctl parser, printer, optimizer, tables and loads"
	local_case pf_table sys/net/pf_table "table hit/miss and flags"
	local_case pf_trans sys/net/pf_trans "transaction ioctl limits"
	local_case pf_print sys/net/pf_print "address/port printing"
	local_case pf_opts sys/net/pf_opts "IP options and IPv6 extension headers"
	local_case pflog sys/net/pflog "pflog(4) and log options"
	local_case pflow sys/net/pflow "pflow(4) IPFIX export"
	topology_case pf_policy sys/net/pf_policy "rule evaluation order (needs remote host)"
	topology_case pf_forward sys/net/pf_forward "forwarding, NAT, af-to, route-to/reply-to"
	topology_case pf_fragment sys/net/pf_fragment "fragment reassembly and refragmentation"
	topology_case pf_state sys/net/pf_state "TCP state validation"
	topology_case pf_divert sys/net/pf_divert "divert-to, divert-reply, divert-packet"
}
