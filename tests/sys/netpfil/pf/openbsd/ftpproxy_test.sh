#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 The 5BSD Project
#
# ftp-proxy(8) (OpenBSD) on a NAT router: a client behind the router
# fetches a file from a server outside in passive and active mode.  The
# client and the server run in vnet jails; the host routes, translates and
# runs pf and ftp-proxy.

. $(atf_get_srcdir)/../../../common/vnet.subr

FTPD=$(atf_get_srcdir)/ftpd.py

ftp_setup()
{
	vnet_init
	kldstat -q -m pf || atf_skip "pf is not loaded"
	which python3 >/dev/null 2>&1 || atf_skip "python3 is required"

	ec=$(vnet_mkepair)
	es=$(vnet_mkepair)
	vnet_mkjail ftpcl ${ec}b
	vnet_mkjail ftpsrv ${es}b
	ifconfig ${ec}a inet 192.0.2.1/24 up
	ifconfig ${es}a inet 198.51.100.1/24 up
	jexec ftpcl ifconfig lo0 inet 127.0.0.1/8 up
	jexec ftpcl ifconfig ${ec}b inet 192.0.2.2/24 up
	jexec ftpcl route -q add default 192.0.2.1
	jexec ftpsrv ifconfig lo0 inet 127.0.0.1/8 up
	jexec ftpsrv ifconfig ${es}b inet 198.51.100.21/24 up
	sysctl -q net.inet.ip.forwarding=1 >/dev/null

	printf '%s\n' \
	    'anchor "ftp-proxy/*"' \
	    "pass in quick on ${ec}a inet proto tcp to port 21 divert-to 127.0.0.1 port 8021" \
	    'pass all' \
	    "match out on ${es}a inet from 192.0.2.0/24 nat-to (${es}a)" |
	    atf_check -s exit:0 -o ignore -e ignore pfctl -f -
	# Restored by the cleanup: later cases expect the host pf as it was.
	pfctl -si 2>/dev/null | grep -q "^Status: Enabled" || touch pf.was_disabled
	pfctl -e >/dev/null 2>&1 || true

	# The server sees only the router's address.
	jot -b 5BSD-ftp-proxy-test 2000 > payload
	jexec ftpsrv python3 ${FTPD} 198.51.100.21 21 test.txt $(pwd)/payload \
	    > ftpd.out 2>&1 &
	echo $! > ftpd.pid
	/usr/sbin/ftp-proxy -d -D 7 > proxy.log 2>&1 &
	echo $! > proxy.pid
	i=0
	until grep -q READY ftpd.out 2>/dev/null &&
	    sockstat -4 -l -p 8021 | grep -q ftp-proxy; do
		i=$((i + 1))
		[ $i -lt 100 ] || atf_fail "ftpd or ftp-proxy did not start"
		sleep 0.1
	done
}

ftp_cleanup()
{
	[ -f proxy.pid ] && kill $(cat proxy.pid) >/dev/null 2>&1
	[ -f ftpd.pid ] && kill $(cat ftpd.pid) >/dev/null 2>&1
	pkill -f "ftpd.py 198.51.100.21" >/dev/null 2>&1
	pfctl -a 'ftp-proxy/*' -Fa >/dev/null 2>&1
	pfctl -Fa >/dev/null 2>&1
	[ -f pf.was_disabled ] && pfctl -q -d >/dev/null 2>&1
	pfctl -f /etc/pf.conf >/dev/null 2>&1
	vnet_cleanup
}

# fetch <ftp option>
fetch()
{
	rm -f fetched
	jexec ftpcl ftp $1 -V -o $(pwd)/fetched ftp://198.51.100.21/test.txt ||
	    atf_fail "ftp $1 failed: $(tail -20 proxy.log)"
	cmp -s payload fetched || atf_fail "ftp $1: file differs"
}

atf_test_case "passive" "cleanup"
passive_head()
{
	atf_set descr 'Passive FTP (EPSV and PASV) through ftp-proxy and NAT'
	atf_set require.user root
}
passive_body()
{
	ftp_setup
	fetch -p
	# The connection went through the proxy, which saw the passive request.
	atf_check -s exit:0 -o match:'client: (EPSV|PASV)' cat proxy.log
}
passive_cleanup()
{
	ftp_cleanup
}

atf_test_case "active" "cleanup"
active_head()
{
	atf_set descr 'Active FTP (PORT and EPRT) through ftp-proxy and NAT'
	atf_set require.user root
}
active_body()
{
	ftp_setup
	fetch -A
	atf_check -s exit:0 -o match:'client: (EPRT|PORT)' cat proxy.log
}
active_cleanup()
{
	ftp_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "passive"
	atf_add_test_case "active"
}
