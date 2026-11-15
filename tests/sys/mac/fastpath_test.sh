#
# SPDX-License-Identifier: BSD-2-Clause
#
# Which MAC policies a system call reaches, observed through the
# framework's mac_framework:::hook-done probe (fired for each policy hook
# that runs), for the command's process tree only.
#
# The "pin" cases hold whatever OES and mac_abac are doing.  The "entry"
# cases pin, per policy, whether an entry point is reached by a system
# call when nobody listens to OES and no mac_abac rule names the
# operation: before the idle gates both policies ran on every read(2),
# pipe write and close(2).
#

# hooks_called "command": "hook policy count" lines for the command's
# process tree.
hooks_called()
{
	dtrace -q -x bufsize=4m -n '
mac_framework:::hook-done
/progenyof($target)/
{
	@[stringof(arg0), stringof(arg1)] = count();
}
END
{
	printa("%s %s %@d\n", @);
}' -c "$1" > hooks.out 2> dtrace.err ||
	    atf_fail "dtrace: $(cat dtrace.err)"
	cat hooks.out
}

# called hook policy: exit status 0 iff policy's hook ran.
called()
{
	awk -v h="$1" -v p="$2" '$1 == h && $2 == p { f = 1 } END { exit !f }' \
	    hooks.out
}

require_dtrace()
{
	kldstat -q -m sdt || atf_skip "sdt(4) is not loaded"
}

atf_test_case pin_lookup_walk cleanup
pin_lookup_walk_head()
{
	atf_set descr "stat(2) walks vnode_check_lookup through every policy" \
	    "that implements it: no lockless lookup on this system"
	atf_set require.user root
	atf_set require.progs dtrace
	atf_set is.exclusive true
}
pin_lookup_walk_body()
{
	require_dtrace
	hooks_called "/bin/sh -c 'stat -f %i /etc/passwd >/dev/null'"
	called vnode_check_lookup oes ||
	    atf_fail "oes: vnode_check_lookup not reached"
	called vnode_check_lookup mac_abac ||
	    atf_fail "mac_abac: vnode_check_lookup not reached"
}
pin_lookup_walk_cleanup()
{
	:
}

# entry_case name hook "command" oes-expected abac-expected
# expected: "yes" (the policy's hook runs) or "no".
entry_check()
{
	local hook=$1 cmd=$2 want_oes=$3 want_abac=$4

	require_dtrace
	hooks_called "$cmd"
	if called "$hook" oes; then got=yes; else got=no; fi
	[ "$got" = "$want_oes" ] ||
	    atf_fail "oes $hook reached: $got, expected $want_oes"
	if called "$hook" mac_abac; then got=yes; else got=no; fi
	[ "$got" = "$want_abac" ] ||
	    atf_fail "mac_abac $hook reached: $got, expected $want_abac"
}

# Whether OES and mac_abac are reached with nobody listening, as the
# kernel under test must answer: "yes yes" before the idle gates.
: ${OES_IDLE_ENTRY:=yes}
: ${ABAC_IDLE_ENTRY:=yes}

atf_test_case entry_file_read
entry_file_read_head()
{
	atf_set descr "read(2) of a regular file reaches mac_file_check_read"
	atf_set require.user root
	atf_set require.progs dtrace
	atf_set is.exclusive true
}
entry_file_read_body()
{
	entry_check file_check_read \
	    "/bin/sh -c 'cat /etc/passwd >/dev/null'" \
	    $OES_IDLE_ENTRY $ABAC_IDLE_ENTRY
}

atf_test_case entry_pipe_write
entry_pipe_write_head()
{
	atf_set descr "a pipe write reaches mac_pipe_check_write"
	atf_set require.user root
	atf_set require.progs dtrace
	atf_set is.exclusive true
}
entry_pipe_write_body()
{
	entry_check pipe_check_write \
	    "/bin/sh -c 'echo x | cat >/dev/null'" \
	    $OES_IDLE_ENTRY $ABAC_IDLE_ENTRY
}

atf_test_case entry_close
entry_close_head()
{
	atf_set descr "close(2) of a vnode reaches mac_vnode_check_close"
	atf_set require.user root
	atf_set require.progs dtrace
	atf_set is.exclusive true
}
entry_close_body()
{
	# Only OES implements the close hooks.
	entry_check vnode_check_close \
	    "/bin/sh -c 'cat /etc/passwd >/dev/null'" $OES_IDLE_ENTRY no
	entry_check file_notify_close \
	    "/bin/sh -c 'cat /etc/passwd >/dev/null'" $OES_IDLE_ENTRY no
}

atf_init_test_cases()
{
	atf_add_test_case pin_lookup_walk
	atf_add_test_case entry_file_read
	atf_add_test_case entry_pipe_write
	atf_add_test_case entry_close
}
