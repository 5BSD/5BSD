#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 The 5BSD Project
#
# The 5BSD "jail <name|jid>" pf rule option (sys/netpfil/openbsd-pf/pf_jail.c)
# in a VNET jail's own pf.  Each test creates a VNET jail "fw" with its own
# pf and non-VNET child jails (ip4=inherit) that share fw's network stack,
# the way service jails share a host's stack.  The rule matches the jail of
# the local socket, so jails with the same addresses get different policies.
# Names given inside fw are relative to fw (fw.web is "web" there).
# tests/sys/netpfil/pf/openbsd/jail_test.sh covers the same option in the
# host vnet.

. $(atf_get_srcdir)/integration.subr

ADDR=198.51.100.1

# jr_setup: VNET jail fw with pf enabled, ADDR on its loopback.
jr_setup()
{
	pft_init
	jail -c name=fw persist vnet children.max=8 ||
	    atf_fail "cannot create the VNET jail fw"
	echo fw >> created_jails.lst
	jexec fw ifconfig lo0 inet 127.0.0.1/8 up
	jexec fw ifconfig lo0 inet ${ADDR}/32 alias
	atf_check -s exit:0 -e ignore jexec fw pfctl -e
}

# jr_child name: a non-VNET child jail of fw sharing fw's stack.
jr_child()
{
	jexec fw jail -c name=$1 persist ip4=inherit ip6=inherit ||
	    atf_fail "cannot create child jail fw.$1"
}

jr_jid()
{
	jls -j $1 jid
}

# jr_listen jail port [user]: TCP listener on ADDR in a jail.
jr_listen()
{
	_u=
	[ -n "$3" ] && _u="-U $3"
	jexec ${_u} $1 nc -l -k ${ADDR} $2 >/dev/null 2>&1 &
	jr_wait_listen $2 tcp
}

# jr_listen_udp jail port outfile: UDP receiver on ADDR in a jail.
jr_listen_udp()
{
	: > $3
	jexec $1 nc -u -l ${ADDR} $2 > $3 2>/dev/null &
	jr_wait_listen $2 udp
}

jr_wait_listen()
{
	_i=0
	while ! jexec fw sockstat -4 -P $2 -p $1 | grep -q "${ADDR}:$1"; do
		_i=$((_i + 1))
		[ ${_i} -lt 50 ] || atf_fail "no $2 listener on port $1"
		sleep 0.1
	done
}

jr_rules()
{
	pft_set_rules fw "$@"
}

# jr_conn from port: exit status of a TCP connect from jail "from".
jr_conn()
{
	jexec $1 nc -z -w 2 ${ADDR} $2 >/dev/null 2>&1
}

# jr_wait_conn from port 0|1: wait until the connection is blocked (0) or
# passes (1); jail events re-resolve named rules from a task.
jr_wait_conn()
{
	_i=0
	while :; do
		if jr_conn $1 $2; then _r=1; else _r=0; fi
		[ ${_r} = $3 ] && return 0
		_i=$((_i + 1))
		[ ${_i} -lt 30 ] || atf_fail "$1 -> port $2: expected $3"
		sleep 0.2
	done
}

atf_test_case "tcp_name_jid" "cleanup"
tcp_name_jid_head()
{
	atf_set descr 'jail by name and by jid selects TCP sockets of child jails sharing a VNET stack'
	atf_set require.user root
}
tcp_name_jid_body()
{
	jr_setup
	jr_child web
	jr_child db
	jw=$(jr_jid fw.web)
	jd=$(jr_jid fw.db)
	jr_listen fw.web 8001
	jr_listen fw.db 8002

	# Without a jail rule both listeners answer.
	jr_rules "pass all"
	atf_check -s exit:0 -e ignore jexec fw nc -z -w 2 ${ADDR} 8001
	atf_check -s exit:0 -e ignore jexec fw nc -z -w 2 ${ADDR} 8002

	# Inbound, by relative name: the listening socket's jail decides.
	jr_rules "pass all" "block in quick proto tcp to ${ADDR} jail web"
	atf_check -s not-exit:0 -e ignore jexec fw nc -z -w 2 ${ADDR} 8001
	atf_check -s exit:0 -e ignore jexec fw nc -z -w 2 ${ADDR} 8002
	# Printed relative to fw, as loaded.
	atf_check -s exit:0 -o match:'jail = web' -o not-match:'fw\.web' \
	    jexec fw pfctl -sr

	# By jail id, and negated.
	jr_rules "pass all" "block in quick proto tcp to ${ADDR} jail ${jd}"
	atf_check -s exit:0 -e ignore jexec fw nc -z -w 2 ${ADDR} 8001
	atf_check -s not-exit:0 -e ignore jexec fw nc -z -w 2 ${ADDR} 8002
	atf_check -s exit:0 -o match:"jail = ${jd}" jexec fw pfctl -sr
	jr_rules "pass all" "block in quick proto tcp to ${ADDR} jail != ${jw}"
	atf_check -s exit:0 -e ignore jexec fw nc -z -w 2 ${ADDR} 8001
	atf_check -s not-exit:0 -e ignore jexec fw nc -z -w 2 ${ADDR} 8002

	# Outbound: the connecting socket's jail decides.
	jr_rules "pass all" "block out quick proto tcp to ${ADDR} jail db"
	atf_check -s exit:0 -e ignore jexec fw.web nc -z -w 2 ${ADDR} 8002
	atf_check -s not-exit:0 -e ignore jexec fw.db nc -z -w 2 ${ADDR} 8001
	atf_check -s exit:0 -e ignore jexec fw nc -z -w 2 ${ADDR} 8001

	# A list expands to one rule per jail.
	jr_rules "pass all" "block out quick proto tcp to ${ADDR} jail { web db }"
	atf_check -s exit:0 -o match:'jail = web' -o match:'jail = db' \
	    jexec fw pfctl -sr
	atf_check -s not-exit:0 -e ignore jexec fw.web nc -z -w 2 ${ADDR} 8002
	atf_check -s not-exit:0 -e ignore jexec fw.db nc -z -w 2 ${ADDR} 8001
	atf_check -s exit:0 -e ignore jexec fw nc -z -w 2 ${ADDR} 8002
}
tcp_name_jid_cleanup()
{
	integ_cleanup
}

atf_test_case "udp" "cleanup"
udp_head()
{
	atf_set descr 'jail matches UDP sockets inbound (receiver) and outbound (sender)'
	atf_set require.user root
}
udp_body()
{
	jr_setup
	jr_child web
	jr_child db

	jr_rules "pass all" "block in quick proto udp to ${ADDR} jail web"
	jr_listen_udp fw.web 8101 web.out
	jr_listen_udp fw.db 8102 db.out
	echo to-web | jexec fw nc -u -w 1 ${ADDR} 8101
	echo to-db | jexec fw nc -u -w 1 ${ADDR} 8102
	sleep 1
	atf_check -s exit:0 -o empty cat web.out
	atf_check -s exit:0 -o inline:'to-db\n' cat db.out

	# Outbound: datagrams sent by db are dropped, web's arrive.
	jr_rules "pass all" "block out quick proto udp to ${ADDR} port 8103 jail db"
	jr_listen_udp fw 8103 fw.out
	echo from-db | jexec fw.db nc -u -w 1 ${ADDR} 8103
	sleep 1
	atf_check -s exit:0 -o empty cat fw.out
	echo from-web | jexec fw.web nc -u -w 1 ${ADDR} 8103
	sleep 1
	atf_check -s exit:0 -o inline:'from-web\n' cat fw.out
	# The block rule counted the dropped datagram.
	atf_check -s exit:0 -o match:'Packets: [1-9]' \
	    sh -c "jexec fw pfctl -vsr | grep -A2 'jail = db'"
}
udp_cleanup()
{
	integ_cleanup
}

atf_test_case "with_user" "cleanup"
with_user_head()
{
	atf_set descr 'jail combined with user matches only sockets of that user in that jail'
	atf_set require.user root
}
with_user_body()
{
	jr_setup
	jr_child web
	jr_child db

	jr_listen fw.web 8201 nobody
	jr_listen fw.web 8202
	jr_listen fw.db 8203 nobody

	jr_rules "pass all" \
	    "block in quick proto tcp to ${ADDR} user nobody jail web"
	atf_check -s exit:0 -o match:'user = 65534' -o match:'jail = web' \
	    jexec fw pfctl -sr
	# nobody in web: blocked; root in web: passes; nobody in db: passes.
	atf_check -s not-exit:0 -e ignore jexec fw nc -z -w 2 ${ADDR} 8201
	atf_check -s exit:0 -e ignore jexec fw nc -z -w 2 ${ADDR} 8202
	atf_check -s exit:0 -e ignore jexec fw nc -z -w 2 ${ADDR} 8203
}
with_user_cleanup()
{
	integ_cleanup
}

atf_test_case "rename" "cleanup"
rename_head()
{
	atf_set descr 'A named rule follows jail renames (jail -m name=) without a reload'
	atf_set require.user root
}
rename_body()
{
	jr_setup
	jr_child web
	jw=$(jr_jid fw.web)
	jr_listen fw.web 8301

	jr_rules "pass all" "block in quick proto tcp to ${ADDR} jail web"
	jr_wait_conn fw 8301 0

	# Renamed away: no jail is called web, the rule matches nothing.
	atf_check -s exit:0 jexec fw jail -m jid=${jw} name=web2
	atf_check -s exit:0 -o inline:"fw.web2\n" jls -j ${jw} name
	jr_wait_conn fw 8301 1
	atf_check -s exit:0 -o match:'jail = web' jexec fw pfctl -sr

	# A different jail now takes the name: the rule follows the name.
	jr_child web
	jr_listen fw.web 8302
	jr_wait_conn fw 8302 0
	atf_check -s exit:0 -e ignore jexec fw nc -z -w 2 ${ADDR} 8301

	# Renaming the first jail back while the name is taken fails.
	atf_check -s not-exit:0 -e ignore jexec fw jail -m jid=${jw} name=web
}
rename_cleanup()
{
	integ_cleanup
}

atf_test_case "recreate" "cleanup"
recreate_head()
{
	atf_set descr 'Named rules re-resolve on jail creation and re-creation; jail ids stay literal'
	atf_set require.user root
}
recreate_body()
{
	jr_setup

	# Loaded before the jail exists.
	jr_rules "pass all" \
	    "block in quick proto tcp to ${ADDR} port 8401 jail web"
	jr_child web
	j1=$(jr_jid fw.web)
	jr_listen fw.web 8401
	jr_wait_conn fw 8401 0

	# Removed and created again with a new jail id: still matched.
	atf_check -s exit:0 jexec fw jail -r web
	jr_child web
	j2=$(jr_jid fw.web)
	[ "${j1}" != "${j2}" ] || atf_fail "jail id was reused"
	jr_listen fw.web 8401
	jr_wait_conn fw 8401 0

	# A numeric jail id is literal: the old id matches nothing now.
	jr_rules "pass all" \
	    "block in quick proto tcp to ${ADDR} port 8401 jail ${j1}"
	atf_check -s exit:0 -o match:"jail = ${j1}" jexec fw pfctl -sr
	jr_wait_conn fw 8401 1
}
recreate_cleanup()
{
	integ_cleanup
}

atf_test_case "relative_names" "cleanup"
relative_names_head()
{
	atf_set descr 'Rule jail names inside a VNET jail are relative to it'
	atf_set require.user root
}
relative_names_body()
{
	jr_setup
	jr_child web
	jr_listen fw.web 8501

	# "fw.web" given inside fw means fw.fw.web, which does not exist.
	jr_rules "pass all" "block in quick proto tcp to ${ADDR} jail fw.web"
	atf_check -s exit:0 -e ignore jexec fw nc -z -w 2 ${ADDR} 8501
	atf_check -s exit:0 -o match:'jail = fw\.web' jexec fw pfctl -sr

	# The relative name selects the child.
	jr_rules "pass all" "block in quick proto tcp to ${ADDR} jail web"
	atf_check -s not-exit:0 -e ignore jexec fw nc -z -w 2 ${ADDR} 8501

	# The host's pf does not see fw's rules.
	atf_check -s exit:0 -o not-match:'jail = web' pfctl -sr
}
relative_names_cleanup()
{
	integ_cleanup
}

atf_test_case "vnet_own_jid" "cleanup"
vnet_own_jid_head()
{
	atf_set descr 'Sockets of the VNET jail itself carry its jail id, not 0'
	atf_set require.user root
}
vnet_own_jid_body()
{
	jr_setup
	jr_child web
	jf=$(jr_jid fw)
	jr_listen fw.web 8601

	# jail 0 is the host's prison: no socket in fw's stack belongs to it.
	jr_rules "pass all" "block out quick proto tcp to ${ADDR} jail 0"
	atf_check -s exit:0 -e ignore jexec fw nc -z -w 2 ${ADDR} 8601
	# fw's own sockets are matched by fw's jail id; its child is not.
	jr_rules "pass all" "block out quick proto tcp to ${ADDR} jail ${jf}"
	atf_check -s not-exit:0 -e ignore jexec fw nc -z -w 2 ${ADDR} 8601
	atf_check -s exit:0 -e ignore jexec fw.web nc -z -w 2 ${ADDR} 8601
}
vnet_own_jid_cleanup()
{
	integ_cleanup
}

atf_test_case "forwarded" "cleanup"
forwarded_head()
{
	atf_set descr 'Forwarded packets have no socket: jail = never matches them, jail != does'
	atf_set require.user root
}
forwarded_body()
{
	pft_init
	epair_c=$(vnet_mkepair)
	epair_s=$(vnet_mkepair)
	vnet_mkjail rtr ${epair_c}b ${epair_s}a
	vnet_mkjail cli ${epair_c}a
	vnet_mkjail srv ${epair_s}b
	jexec rtr ifconfig ${epair_c}b 192.0.2.1/24 up
	jexec rtr ifconfig ${epair_s}a 203.0.113.1/24 up
	jexec rtr sysctl -q net.inet.ip.forwarding=1
	jexec cli ifconfig ${epair_c}a 192.0.2.2/24 up
	jexec cli route -q add default 192.0.2.1
	jexec srv ifconfig ${epair_s}b 203.0.113.2/24 up
	jexec srv route -q add default 203.0.113.1
	jexec srv nc -l -k 203.0.113.2 8701 >/dev/null 2>&1 &
	sleep 1
	jexec rtr pfctl -e >/dev/null 2>&1
	rj=$(jls -j rtr jid)

	# "jail <id>" and "jail 0" never match a packet without a socket.
	pft_set_rules rtr "pass all" \
	    "block quick proto tcp to port 8701 jail ${rj}" \
	    "block quick proto tcp to port 8701 jail 0"
	atf_check -s exit:0 -e ignore jexec cli nc -z -w 2 203.0.113.2 8701
	# As with "user !=", a negated jail matches the unknown socket
	# (pf_match_jail compares lookup.jid -1 with !=).
	pft_set_rules rtr "pass all" \
	    "block quick proto tcp to port 8701 jail != ${rj}"
	atf_check -s not-exit:0 -e ignore jexec cli nc -z -w 2 203.0.113.2 8701
}
forwarded_cleanup()
{
	integ_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "tcp_name_jid"
	atf_add_test_case "udp"
	atf_add_test_case "with_user"
	atf_add_test_case "rename"
	atf_add_test_case "recreate"
	atf_add_test_case "relative_names"
	atf_add_test_case "vnet_own_jid"
	atf_add_test_case "forwarded"
}
