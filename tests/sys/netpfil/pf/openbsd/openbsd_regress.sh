#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
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
	local corpus work log make_status trans_timeout

	# Keep the complete pf_trans suite, but allow slow disposable guests
	# the upstream dev-limit maximum dwell (strtonum accepts 1..60).
	if [ "${dir}" = sys/net/pf_trans ]; then
		trans_timeout=$(atf_config_get openbsd_regress_pf_trans_timeout 10)
		case "${trans_timeout}" in
		''|*[!0-9]*) atf_fail "pf_trans timeout must be an integer in 1..60" ;;
		esac
		[ "${trans_timeout}" -ge 1 ] && [ "${trans_timeout}" -le 60 ] || \
		    atf_fail "pf_trans timeout must be an integer in 1..60"
		set -- "$@" "TIMEOUT=${trans_timeout}"
	fi

	corpus=$(srctree)
	[ -d "${corpus}/regress/${dir}" ] || atf_skip "corpus not installed"
	kldstat -q -m pf || atf_skip "pf is not loaded"
	# Kyua runs this in a new VNET jail: give it what an OpenBSD regress
	# machine has (tools/test/pf-parity/openbsd-regress/setup-dut-5bsd.sh):
	# lo0 addresses, pf enabled with an anchor "regress", pflog0.
	if [ "$(sysctl -n security.jail.jailed)" = 1 ]; then
		ifconfig lo0 inet 127.0.0.1/8 up
		ifconfig lo0 inet6 ::1 prefixlen 128 no_dad 2>/dev/null || true
		printf 'pass\nanchor "regress"\n' | pfctl -q -f -
		pfctl -q -e 2>/dev/null || true
		ifconfig pflog0 create >/dev/null 2>&1 || true
	fi
	# Upstream Makefiles locate helpers through relative paths, so keep the
	# upstream layout (regress/... next to sbin/ and sys/).
	work=$(pwd)/src
	mkdir -p "${work}"
	# and the sources they build from (pf_print: sys/net/pf.c).
	for d in regress sbin sys usr.sbin; do
		[ -d "${corpus}/${d}" ] && cp -R "${corpus}/${d}" "${work}/"
	done
	log=$(pwd)/regress.log
	: > "${log}"
	make_status=0
	(cd "${work}/regress/${dir}" && \
	    env MAKESYSPATH="$(atf_get_srcdir)/mk:/usr/share/mk" \
	    BSDSRCDIR="${work}" make REGRESS_LOG="${log}" REGRESS_FAIL_EARLY=no \
	    "$@" regress) > out 2>&1 || make_status=$?
	cat out
	echo "==== REGRESS_LOG BEGIN ===="
	cat "${log}"
	echo "==== REGRESS_LOG END ===="
	# REGRESS_FAIL_EARLY=no lets per-target FAIL/XPASS complete the
	# log, but does not excuse make/setup/cleanup errors after a SUCCESS.
	[ "${make_status}" -eq 0 ] || \
	    atf_fail "upstream make failed (status ${make_status}); see out"
	if ! grep -q . "${log}"; then
		# Some suite Makefiles override regress with a whole-suite skip.
		grep -qx SKIPPED out && atf_skip "upstream suite skipped: $(grep -B2 '^SKIPPED$' out | head -2 | tr '\n' ' ')"
		atf_fail "no per-target results"
	fi
	# bsd.regress.mk emits exactly STATUS suite/target. Reject partial
	# records, unexpected status words and arbitrary nonempty output.
	awk '$0 !~ /^(SUCCESS|SKIP|XFAIL|FAIL|XPASS) [^[:space:]]+$/ { exit 1 }' \
	    "${log}" || atf_fail "malformed per-target results"
	if grep -Eq '^(FAIL|XPASS) ' "${log}"; then
		atf_fail "$(grep -Ec '^(FAIL|XPASS) ' "${log}") failed or unexpectedly passed: $(grep -E '^(FAIL|XPASS) ' "${log}" | sed 's,.*/,,' | tr '\n' ' ')"
	fi
	grep -Eq '^(SUCCESS|XFAIL) ' "${log}" || \
	    atf_skip "all upstream targets skipped"
}

local_case()
{
	local name=$1 dir=$2 descr=$3
	# Whole upstream suites: pf_opts alone takes ten minutes on a test VM.
	eval "${name}_head() { atf_set descr '${descr}'; atf_set require.user root; atf_set timeout 1200; }"
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
