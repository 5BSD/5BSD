#
# SPDX-License-Identifier: BSD-2-Clause
#
# OpenBSD's pfctl regression corpus (contrib/openbsd-pf/regress/sbin/pfctl)
# under ATF.  The corpus and its Makefile are installed unchanged in files/;
# the Makefile is installed as regress.mk and the test lists (PFTESTS,
# PFFAIL, ...) are read from it, so a corpus update needs no change here.
# Each case runs the recipe of the OpenBSD target of the same name.
#
# Every case runs in its own VNET (Kyua execenv=jail, see the Makefile):
# the corpus refers to lo1000000, tun1000000 and tun1000001, which the
# OpenBSD Makefile creates in .BEGIN, and the kernel cases load rules into
# the anchor "regress" and the main ruleset.
#
# The parse-only targets (pf, selfpf, pfail, pfsimple, pfopt, pfcmdfail)
# do not change the kernel; PFCTL may name another pfctl binary.

: ${PFCTL:=/sbin/pfctl}
export PFCTL

regress_files()
{
	echo "$(atf_get_srcdir)/files"
}

# regress_list VAR: the values of VAR= and VAR+= in the OpenBSD Makefile.
regress_list()
{
	awk -v v="$1" '
	    $0 ~ "^" v "[+]?=" {
		sub("^" v "[+]?=", "")
		print
	    }' "$(regress_files)/regress.mk" | tr -s ' \t' '\n\n' | grep -v '^$'
}

# Cases that also fail on the OpenBSD reference system (same corpus, run
# on OpenBSD 8.0-current: /usr/obj/5BSD-pf-parity/results/openbsd-baseline1).
# They are stale upstream expectations, not 5BSD differences:
#  pfr1-6, pfr8-15: the .ok files predate anchor-qualified table names in
#      "pfctl -sT" ("regress@regress") and the current ktable pool counts;
#  pfsetup1: the .ok predates the change that prints an interface address
#      without the network prefix and without "keep state";
#  pfchksum1-3: the expected checksums predate rule-layout changes.
# They run as expected failures, so a corpus update that fixes them shows up
# as an unexpected pass.
regress_known_failure()
{
	case "$1" in
	pfr[1-6]|pfr[89]|pfr1[0-5]|pfsetup1|pfchksum[1-3])
		return 0
		;;
	esac
	return 1
}

regress_mkifs()
{
	for _if in lo1000000 tun1000000 tun1000001; do
		ifconfig ${_if} create >/dev/null 2>&1 ||
		    ifconfig ${_if} >/dev/null 2>&1 ||
		    atf_fail "cannot create ${_if}"
		echo ${_if} >> regress_ifs.lst
	done
}

regress_cleanup()
{
	if [ -f regress_ifs.lst ]; then
		while read _if; do
			ifconfig ${_if} destroy >/dev/null 2>&1
		done < regress_ifs.lst
		rm -f regress_ifs.lst
	fi
	if [ -c /dev/pf ]; then
		${PFCTL} -o none -a 'regress/*' -Fr >/dev/null 2>&1
		${PFCTL} -o none -a regress -FT >/dev/null 2>&1
	fi
	return 0
}

# regress_diff expected actual: fail the case with the diff on a mismatch.
regress_diff()
{
	if ! diff -u "$1" "$2"; then
		atf_fail "output differs from $(basename "$1")"
	fi
}

# pf39 and pf41 name the groups nobody and sshd; their expected output has
# OpenBSD's ids (32767 and 27).  Expect the local ids instead (FreeBSD's
# nobody is 65534 and sshd 22) rather than renumbering the test system's
# groups.
regress_expected()
{
	_nobody=$(getent group nobody | cut -d: -f3)
	_sshd=$(getent group sshd | cut -d: -f3)
	sed -e "s/group = 32767\([^0-9]\)/group = ${_nobody:-32767}\1/g" \
	    -e "s/group = 27\([^0-9]\)/group = ${_sshd:-27}\1/g" \
	    -e "s/group = 32767\$/group = ${_nobody:-32767}/" \
	    -e "s/group = 27\$/group = ${_sshd:-27}/" "$1" > expected
	echo expected
}

# The include and anchor files are named relative to the working directory
# (the OpenBSD Makefile links them into its object directory).
regress_links()
{
	for _f in pf95.include pf103.include pf112.one pf112.two \
	    pf113.one pf113.two; do
		ln -sf "$(regress_files)/${_f}" "${_f}"
	done
}

# pfr.exec and if2ip are ksh scripts.  Make sh copies: "let" becomes
# arithmetic expansion and ksh's escape-expanding echo becomes printf.
regress_shcopy()
{
	sed -e '1s,^#!.*,#!/bin/sh,' \
	    -e 's/^let \([A-Z_]*\)=\(.*\)$/\1=$((\2))/' \
	    -e 's/echo "# test\\n" \$ARGSX/printf "# test\\n %s\\n" "$(echo $ARGSX)"/' \
	    "$(regress_files)/$1" > "$1.sh"
}

#
# Recipes, one per OpenBSD target.
#

run_pf()
{
	f=$(regress_files)
	regress_links
	${PFCTL} -o none -nv -f - < $f/pf$1.in > out
	regress_diff $(regress_expected $f/pf$1.ok) out
}

run_selfpf()
{
	f=$(regress_files)
	regress_links
	${PFCTL} -o none -nv -f - < $f/pf$1.ok > out
	regress_diff $f/pf$1.ok out
}

run_pfail()
{
	f=$(regress_files)
	${PFCTL} -o none -nv -f - < $f/pfail$1.in > out 2>&1
	regress_diff $f/pfail$1.ok out
}

run_pfsimple()
{
	f=$(regress_files)
	${PFCTL} -o none -nf - < $f/pfsimple$1.in ||
	    atf_fail "pfctl rejected pfsimple$1.in"
}

run_pfopt()
{
	f=$(regress_files)
	${PFCTL} -o none -nv -f - $(cat $f/pfopt$1.opts) < $f/pfopt$1.in > out
	regress_diff $f/pfopt$1.ok out
}

run_pfcmd()
{
	f=$(regress_files)
	${PFCTL} $(cat $f/pfcmd$1.opts) -f $f/pfcmd$1.in ||
	    atf_fail "pfctl $(cat $f/pfcmd$1.opts) failed"
}

run_pfcmdfail()
{
	f=$(regress_files)
	${PFCTL} $(cat $f/pfcmdfail$1.opts) -f - < $f/pfcmdfail$1.in > out 2>&1
	regress_diff $f/pfcmdfail$1.ok out
}

run_pfload()
{
	f=$(regress_files)
	regress_links
	${PFCTL} -o none -a regress -f - < $f/pf$1.in ||
	    atf_fail "cannot load pf$1.in into anchor regress"
	${PFCTL} -o none -a 'regress/*' -gvvsr |
	    sed -e 's/__automatic_[0-9a-f]*_/__automatic_/g' > out
	regress_diff $(regress_expected $f/pf$1.loaded) out
}

run_pfoptimize()
{
	f=$(regress_files)
	regress_links
	${PFCTL} -obasic -a regress -f - < $f/pf$1.in ||
	    atf_fail "cannot load pf$1.in into anchor regress"
	${PFCTL} -o none -a regress -gvvsr |
	    sed -e 's/__automatic_[0-9a-f]*_/__automatic_/g' > out
	regress_diff $(regress_expected $f/pf$1.optimized) out
}

run_pfr()
{
	f=$(regress_files)
	regress_shcopy pfr.exec
	/bin/sh pfr.exec.sh $f/pfr$1.in > out
	regress_diff $f/pfr$1.ok out
}

run_pfi()
{
	f=$(regress_files)
	regress_shcopy if2ip
	xargs /bin/sh if2ip.sh < $f/pfi$1.in > out
	regress_diff $f/pfi$1.ok out
}

run_pfsetup()
{
	f=$(regress_files)
	/bin/sh $f/pfsetup$1.setup || atf_fail "pfsetup$1.setup failed"
	${PFCTL} -o none -nv -f - < $f/pfsetup$1.in > out
	/bin/sh $f/pfsetup$1.clean
	regress_diff $f/pfsetup$1.ok out
}

run_pfchksum()
{
	f=$(regress_files)
	${PFCTL} -o none -Fa >/dev/null 2>&1
	${PFCTL} -o none -f - < $f/pfchksum$1.in ||
	    atf_fail "cannot load pfchksum$1.in"
	${PFCTL} -o none -vsi | grep '^Checksum:' > out
	${PFCTL} -o none -Fa >/dev/null 2>&1
	regress_diff $f/pfchksum$1.ok out
}

run_pfloadanchors()
{
	f=$(regress_files)
	regress_links
	${PFCTL} -a regress -v -f - < $f/pf$1.in ||
	    atf_fail "cannot load pf$1.in into anchor regress"
	${PFCTL} -a 'regress/*' -sr |
	    sed -e 's/__automatic_[0-9a-f]*_.*>/__automatic_>/' > out
	regress_diff $f/pf$1.ok out
}

# pf-changerule: DIOCCHANGERULE through the changerule helper.
run_changerule()
{
	f=$(regress_files)
	cr=$(atf_get_srcdir)/changerule
	[ -x "${cr}" ] || atf_skip "changerule helper is not installed"

	echo 'pass all' | ${PFCTL} -a regress -f - || atf_fail "load"
	${PFCTL} -a 'regress/*' -Fr
	echo 'pass all' | ${PFCTL} -a regress -f -
	for i in 10 20 30 40 50; do
		echo "pass in proto tcp from any to any port $i" |
		    ${cr} -a regress -i 0 || atf_fail "changerule -i 0"
	done
	${PFCTL} -a regress -sr > out
	regress_diff $f/changerule-head.ok out

	${PFCTL} -a 'regress/*' -Fr
	echo 'pass all' | ${PFCTL} -a regress -f -
	for i in 10 20 30 40 50; do
		echo "pass in proto tcp from any to any port $i" |
		    ${cr} -a regress -i -1 || atf_fail "changerule -i -1"
	done
	${PFCTL} -a regress -sr > out
	regress_diff $f/changerule-tail.ok out

	echo 'pass in proto tcp from any to any port 15' |
	    ${cr} -a regress -i 2 || atf_fail "changerule -i 2"
	${PFCTL} -a regress -sr > out
	regress_diff $f/changerule-before.ok out

	echo 'pass in proto tcp from any to any port 25' |
	    ${cr} -a regress -I 3 || atf_fail "changerule -I 3"
	${PFCTL} -a regress -sr > out
	regress_diff $f/changerule-after.ok out
	${PFCTL} -a 'regress/*' -Fr
}

# regress_case kind number [list-var]: define and register one case.
regress_case()
{
	_kind=$1
	_n=$2
	_tc=${_kind}${_n}
	atf_test_case ${_tc} cleanup
	_xfail=
	if regress_known_failure ${_tc}; then
		_xfail="atf_expect_fail 'fails on the OpenBSD reference system too (stale upstream expectation)';"
	fi
	eval "${_tc}_head() {
		atf_set descr 'OpenBSD regress/sbin/pfctl target ${_tc}'
		atf_set require.user root
	}"
	eval "${_tc}_body() {
		${_xfail}
		[ -x \"\${PFCTL}\" ] || atf_skip \"\${PFCTL} is not installed\"
		regress_mkifs
		run_${_kind} ${_n}
	}"
	eval "${_tc}_cleanup() { regress_cleanup; }"
	atf_add_test_case ${_tc}
}

atf_init_test_cases()
{
	for n in $(regress_list PFTESTS); do
		regress_case pf $n
		regress_case selfpf $n
	done
	for n in $(regress_list PFFAIL); do
		regress_case pfail $n
	done
	for n in $(regress_list PFSIMPLE); do
		regress_case pfsimple $n
	done
	for n in $(regress_list PFOPT); do
		regress_case pfopt $n
	done
	for n in $(regress_list PFCMD); do
		regress_case pfcmd $n
	done
	for n in $(regress_list PFCMDFAIL); do
		regress_case pfcmdfail $n
	done
	for n in $(regress_list PFLOAD); do
		regress_case pfload $n
		regress_case pfoptimize $n
	done
	for n in $(regress_list PFTABLE); do
		regress_case pfr $n
	done
	for n in $(regress_list PFIF2IP); do
		regress_case pfi $n
	done
	for n in $(regress_list PFSETUP); do
		regress_case pfsetup $n
	done
	for n in $(regress_list PFCHKSUM); do
		regress_case pfchksum $n
	done
	for n in $(regress_list PFLOADANCHORS); do
		regress_case pfloadanchors $n
	done
	regress_case changerule ""
}
