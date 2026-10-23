#
# SPDX-License-Identifier: BSD-2-Clause
#
# Ruleset checksums: pfsync peers match states to rules by the checksum, so
# a ruleset without 5BSD extensions must checksum as it does on OpenBSD.

. $(atf_get_srcdir)/utils.subr

# The checksum pfctl -vsi reports for a ruleset loaded into jail $1.
checksum_of()
{
	jexec $1 pfctl -o none -q -f - || atf_fail "loading the ruleset"
	jexec $1 pfctl -o none -vsi | awk '$1 == "Checksum:" { print $2 }'
}

atf_test_case "openbsd" "cleanup"
openbsd_head()
{
	atf_set descr 'A ruleset without 5BSD extensions has OpenBSD'"'"'s checksum'
	atf_set require.user root
}

openbsd_body()
{
	pft_init
	vnet_mkjail alcatraz

	# Reported by OpenBSD 8.0 for OpenBSD's own regress/sbin/pfctl
	# pfchksum rulesets (whose .ok files predate it).
	for c in 1:0xb8291b45550bb1e2cf9045e9ed30c1c0 \
	    2:0x6a924f87b2e00d5570cfb36894741845 \
	    3:0x566cfbdcf8fac1afecfb41fe35e96989; do
		n=${c%%:*}
		sum=$(checksum_of alcatraz < $(atf_get_srcdir)/pfchksum${n}.in)
		[ "${sum}" = "${c#*:}" ] ||
		    atf_fail "pfchksum${n}: checksum ${sum}, OpenBSD ${c#*:}"
	done
}

openbsd_cleanup()
{
	pft_cleanup
}

atf_test_case "extensions" "cleanup"
extensions_head()
{
	atf_set descr '5BSD jail and dummynet matches change the checksum'
	atf_set require.user root
}

extensions_body()
{
	dummynet_init
	vnet_mkjail alcatraz

	plain=$(echo "pass out proto tcp" | checksum_of alcatraz)
	jail=$(echo "pass out proto tcp jail 1" | checksum_of alcatraz)
	pipe=$(echo "pass out proto tcp dnpipe 1" | checksum_of alcatraz)
	queue=$(echo "pass out proto tcp dnqueue 1" | checksum_of alcatraz)
	echo "plain ${plain} jail ${jail} dnpipe ${pipe} dnqueue ${queue}"
	[ -n "${plain}" ] || atf_fail "no checksum"
	[ "${jail}" != "${plain}" ] || atf_fail "a jail match does not count"
	[ "${pipe}" != "${plain}" ] || atf_fail "a dnpipe does not count"
	[ "${queue}" != "${pipe}" ] ||
	    atf_fail "dnpipe and dnqueue checksum alike"
}

extensions_cleanup()
{
	pft_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "openbsd"
	atf_add_test_case "extensions"
}
