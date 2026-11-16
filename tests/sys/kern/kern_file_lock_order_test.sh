#
# SPDX-License-Identifier: BSD-2-Clause
#
# The kern.file sysctl must not take a descriptor table lock under
# allproc_lock: a table lock is held across vnode locks (knote_fdclose()),
# and vnode-locked paths reach proctree_lock and with it allproc_lock.
# WITNESS records every direct order it sees; the edge must not appear.
#

atf_test_case no_filedesc_under_allproc
no_filedesc_under_allproc_head()
{
	atf_set "descr" "kern.file does not lock a descriptor table under allproc_lock"
	atf_set "require.user" "root"
}
no_filedesc_under_allproc_body()
{
	watch=$(sysctl -n debug.witness.watch 2>/dev/null)
	if [ -z "$watch" ] || [ "$watch" -lt 1 ]; then
		atf_skip "WITNESS is not running"
	fi
	# Open descriptors of our own, so that there is a table to read.
	exec 3</dev/null
	atf_check -s exit:0 -o ignore sysctl -b kern.file
	atf_check -s exit:0 -o save:graph sysctl -n debug.witness.fullgraph
	if grep -qx '"allproc","filedesc structure"' graph; then
		atf_fail "WITNESS recorded allproc -> filedesc structure"
	fi
	# The graph is WITNESS's own: make sure it is not empty.
	atf_check -s exit:0 -o ignore grep -q '^"allproc",' graph
}

atf_init_test_cases()
{
	atf_add_test_case no_filedesc_under_allproc
}
