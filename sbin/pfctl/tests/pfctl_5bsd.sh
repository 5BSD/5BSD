#
# SPDX-License-Identifier: BSD-2-Clause
#
# Parser round trips for the 5BSD extensions to OpenBSD pfctl: the jail
# rule option, ether rules, dnpipe/dnqueue, the sctp.* timeouts and
# allow-related (pf.conf(5), "5BSD:" sections).  Same recipes as the
# OpenBSD corpus (pfctl_regress):
#   extN:      pfctl -nv of files/extN.in prints files/extN.ok;
#   selfextN:  pfctl -nv of files/extN.ok prints it unchanged;
#   extfailN:  pfctl rejects files/extfailN.in with the messages in
#              files/extfailN.ok.
# These cases parse only (pfctl -n) and do not change the kernel.

: ${PFCTL:=/sbin/pfctl}

ext_files()
{
	echo "$(atf_get_srcdir)/files"
}

ext_diff()
{
	if ! diff -u "$1" "$2"; then
		atf_fail "output differs from $(basename "$1")"
	fi
}

run_ext()
{
	f=$(ext_files)
	${PFCTL} -o none -nv -f - < $f/ext$1.in > out ||
	    atf_fail "pfctl rejected ext$1.in"
	ext_diff $f/ext$1.ok out
}

run_selfext()
{
	f=$(ext_files)
	${PFCTL} -o none -nv -f - < $f/ext$1.ok > out ||
	    atf_fail "pfctl rejected its own output ext$1.ok"
	ext_diff $f/ext$1.ok out
}

run_extfail()
{
	f=$(ext_files)
	if ${PFCTL} -o none -nv -f - < $f/extfail$1.in > out 2>&1; then
		cat out
		atf_fail "pfctl accepted extfail$1.in"
	fi
	ext_diff $f/extfail$1.ok out
}

ext_case()
{
	_tc=$1$2
	atf_test_case ${_tc}
	eval "${_tc}_head() {
		atf_set descr '5BSD pfctl extension round trip ${_tc}'
	}"
	eval "${_tc}_body() {
		[ -x \"\${PFCTL}\" ] || atf_skip \"\${PFCTL} is not installed\"
		run_$1 $2
	}"
	atf_add_test_case ${_tc}
}

ext_numbers()
{
	ls "$(ext_files)" | sed -n "s/^$1\([0-9][0-9]*\)\.in\$/\1/p" | sort -n
}

atf_init_test_cases()
{
	for n in $(ext_numbers ext); do
		ext_case ext $n
		ext_case selfext $n
	done
	for n in $(ext_numbers extfail); do
		ext_case extfail $n
	done
}
