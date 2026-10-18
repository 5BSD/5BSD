#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 The 5BSD Project
#
# pf follows OpenBSD at securelevel 2: rule, option and state changes
# fail with EPERM while reads, table address changes and statistics still
# work (pfioctl() in contrib/openbsd-pf/sys/net/pf_ioctl.c; ether rules in
# sys/netpfil/openbsd-pf/pf_ether.c).  5BSD takes the securelevel of the
# calling process's prison (openbsd_compat.h obsd_securelevel()), so the
# host's securelevel, which cannot be lowered again, is never touched:
# each test raises the securelevel of a VNET jail with its own pf.

. $(atf_get_srcdir)/integration.subr

PFIO=$(atf_get_srcdir)/pfiochelper

# sl_jail name: VNET jail with pf enabled, a table and a few rules.
sl_jail()
{
	vnet_mkjail $1
	jexec $1 ifconfig lo0 inet 127.0.0.1/8 up
	atf_check -s exit:0 -e ignore jexec $1 pfctl -e
	pft_set_rules $1 \
	    "table <t> persist { 192.0.2.1 }" \
	    "pass all" \
	    "block in quick inet from <t>"
}

atf_test_case "locked" "cleanup"
locked_head()
{
	atf_set descr 'At jail securelevel 2 pf refuses changes (EPERM) and allows reads and table addresses'
	atf_set require.user root
}
locked_body()
{
	pft_init
	hostlevel=$(sysctl -n kern.securelevel)
	sl_jail sl

	# Below securelevel 2 a direct DIOCADDETHRULE fails on its ticket,
	# not on permissions.
	atf_check -s exit:0 -o match:'^DIOCADDETHRULE=' \
	    -o not-match:'=EPERM' jexec sl ${PFIO} ethadd

	atf_check -s exit:0 jail -m name=sl securelevel=2
	atf_check -s exit:0 -o inline:'2\n' jexec sl sysctl -n kern.securelevel
	atf_check -s exit:0 -o inline:"${hostlevel}\n" sysctl -n kern.securelevel

	# Changes are refused.  pfctl -f fails on its first change: the OS
	# fingerprint flush (EPERM), or opening its transaction (DIOCXBEGIN,
	# reported without errno).
	echo "pass all" | atf_check -s not-exit:0 \
	    -e match:'Operation not permitted|pfctl_rules' jexec sl pfctl -f -
	echo "ether block to 00:01:02:03:04:05" | atf_check -s not-exit:0 \
	    -e match:'Operation not permitted|pfctl_rules' jexec sl pfctl -f -
	atf_check -s exit:0 -o inline:'DIOCADDETHRULE=EPERM\n' \
	    jexec sl ${PFIO} ethadd
	atf_check -s exit:0 -o inline:'DIOCSTART=EPERM\n' jexec sl ${PFIO} start
	atf_check -s not-exit:0 -e match:'Operation not permitted' \
	    jexec sl pfctl -d
	atf_check -s not-exit:0 -e match:'Operation not permitted' \
	    jexec sl pfctl -F states
	atf_check -s not-exit:0 -e match:'Operation not permitted' \
	    jexec sl pfctl -t t -T kill
	# A new table cannot be created; adding to it then fails.
	atf_check -s not-exit:0 -e ignore \
	    jexec sl pfctl -t newtable -T add 192.0.2.5
	atf_check -s exit:0 -o not-match:'newtable' jexec sl pfctl -sT

	# Reads still work, and nothing changed.
	atf_check -s exit:0 -o inline:'DIOCGETSTATUS=ok running=1\n' \
	    jexec sl ${PFIO} getstatus
	atf_check -s exit:0 -o match:'^Status: Enabled' jexec sl pfctl -si
	atf_check -s exit:0 -o match:'block drop in quick inet from <t> to any' \
	    -o match:'^pass all' jexec sl pfctl -sr
	atf_check -s exit:0 -o ignore jexec sl pfctl -ss
	atf_check -s exit:0 -o match:'^t$' jexec sl pfctl -sT
	atf_check -s exit:0 -o match:'192\.0\.2\.1' jexec sl pfctl -t t -T show

	# Table addresses and statistics stay writable (OpenBSD).
	atf_check -s exit:0 -e match:'1/1 addresses added' \
	    jexec sl pfctl -t t -T add 192.0.2.7
	atf_check -s exit:0 -o match:'192\.0\.2\.7' jexec sl pfctl -t t -T show
	atf_check -s exit:0 -e match:'1/1 addresses deleted' \
	    jexec sl pfctl -t t -T delete 192.0.2.7
	atf_check -s exit:0 -e ignore jexec sl pfctl -z

	# The securelevel cannot be lowered again inside the jail.
	atf_check -s not-exit:0 -o ignore -e ignore \
	    jexec sl sysctl kern.securelevel=1
}
locked_cleanup()
{
	integ_cleanup
}

atf_test_case "per_prison" "cleanup"
per_prison_head()
{
	atf_set descr 'Securelevel 2 in one VNET jail does not lock the pf of another jail or the host'
	atf_set require.user root
}
per_prison_body()
{
	pft_init
	sl_jail sl
	sl_jail other
	atf_check -s exit:0 jail -m name=sl securelevel=2

	echo "pass all" | atf_check -s not-exit:0 -e ignore jexec sl pfctl -f -
	# The other jail's pf is still writable.
	pft_set_rules other "pass all" "block in quick inet proto udp"
	atf_check -s exit:0 -o match:'block drop in quick inet proto udp' \
	    jexec other pfctl -sr
	atf_check -s exit:0 -o not-match:'=EPERM' jexec other ${PFIO} ethadd
	# The locked jail kept its own rules.
	atf_check -s exit:0 -o not-match:'proto udp' jexec sl pfctl -sr
	# The host's pf can still be read and its securelevel is unchanged.
	atf_check -s exit:0 -o match:'^Status: ' pfctl -si
	atf_check -s exit:0 -o not-match:'^2$' sysctl -n kern.securelevel
}
per_prison_cleanup()
{
	integ_cleanup
}

atf_test_case "created_locked" "cleanup"
created_locked_head()
{
	atf_set descr 'A VNET jail created at securelevel 2 cannot enable or load pf'
	atf_set require.user root
}
created_locked_body()
{
	pft_init
	jail -c name=sl2 persist vnet securelevel=2 ||
	    atf_fail "cannot create jail sl2"
	echo sl2 >> created_jails.lst

	atf_check -s exit:0 -o inline:'2\n' jexec sl2 sysctl -n kern.securelevel
	atf_check -s not-exit:0 -e match:'Operation not permitted' \
	    jexec sl2 pfctl -e
	echo "pass all" | atf_check -s not-exit:0 \
	    -e match:'pfctl_rules' jexec sl2 pfctl -f -
	atf_check -s exit:0 -o match:'^Status: Disabled' jexec sl2 pfctl -si
	atf_check -s exit:0 -o empty jexec sl2 pfctl -sr
}
created_locked_cleanup()
{
	integ_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "locked"
	atf_add_test_case "per_prison"
	atf_add_test_case "created_locked"
}
