#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# jail_remove(2) of a jail with no processes frees it before it returns:
# the jail is gone from the dying list and a vnet jail's interfaces are
# back in the host vnet.  Callers (rc.d/jail, vnet.subr cleanups) rely on
# both right after "jail -r".  This pins the existing behaviour; a release
# deferred to a task would make either check fail.
#

. $(atf_get_srcdir)/../common/vnet.subr

# Each case repeats the remove to make a deferred free visible.
ITERATIONS=20

atf_test_case "persist_gone_from_dying_list" "cleanup"
persist_gone_from_dying_list_head()
{
	atf_set descr 'jail -r of a persist-only jail leaves no dying jail'
	atf_set require.user root
}
persist_gone_from_dying_list_body()
{
	i=0
	while [ $i -lt $ITERATIONS ]; do
		atf_check jail -c name=jrsync_p persist
		jid=$(jls -j jrsync_p jid)
		atf_check jail -r jrsync_p
		# jls -d lists dying jails; the removed jail must not be one.
		atf_check -s not-exit:0 -o empty -e ignore \
		    jls -d -j "$jid" jid
		i=$((i + 1))
	done
}
persist_gone_from_dying_list_cleanup()
{
	jail -r jrsync_p 2>/dev/null || true
}

atf_test_case "vnet_interface_returned" "cleanup"
vnet_interface_returned_head()
{
	atf_set descr 'jail -r of a persist vnet jail returns its interface'
	atf_set require.user root
}
vnet_interface_returned_body()
{
	vnet_init
	epair=$(ifconfig epair create)
	echo "${epair%a}" > created_epair
	i=0
	while [ $i -lt $ITERATIONS ]; do
		atf_check jail -c name=jrsync_v persist vnet \
		    vnet.interface="$epair"
		atf_check -s not-exit:0 -e ignore ifconfig "$epair"
		atf_check jail -r jrsync_v
		# Back in this vnet as soon as jail -r returns.
		atf_check -o ignore ifconfig "$epair"
		i=$((i + 1))
	done
}
vnet_interface_returned_cleanup()
{
	jail -r jrsync_v 2>/dev/null || true
	if [ -f created_epair ]; then
		ifconfig "$(cat created_epair)a" destroy 2>/dev/null || true
	fi
}

atf_init_test_cases()
{
	atf_add_test_case "persist_gone_from_dying_list"
	atf_add_test_case "vnet_interface_returned"
}
