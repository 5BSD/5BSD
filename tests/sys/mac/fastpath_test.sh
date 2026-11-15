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

# hooks_called "command": "hook policy count" lines for the command
# (one process; its standard output is a pipe).
hooks_called()
{
	dtrace -q -x bufsize=4m -o hooks.out -n '
mac_framework:::hook-done
/pid == $target/
{
	@[stringof(arg0), stringof(arg1)] = count();
}
END
{
	printa("%s %s %@d\n", @);
}' -c "$1" 2> dtrace.err | cat > /dev/null
	[ -s dtrace.err ] && ! grep -q "^dtrace: pid" dtrace.err &&
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
	hooks_called "/usr/bin/stat -f %i /etc/passwd"
	called vnode_check_lookup oes ||
	    atf_fail "oes: vnode_check_lookup not reached"
	called vnode_check_lookup mac_abac ||
	    atf_fail "mac_abac: vnode_check_lookup not reached"
}
pin_lookup_walk_cleanup()
{
	:
}

# fp_expect_called hook policy: "yes" if the snapshot in fp.txt has the
# hook's flag set and the policy implementing it, else "no".
fp_expect_called()
{
	local bit flags impl

	awk '/^hook /' fp.txt > fp.hooks
	awk '/^policy /' fp.txt > fp.policies
	bit=$(awk -v h="$1" '$2 == h { print NR - 1 }' fp.hooks)
	flags=$(awk '/^flags / { print $2 }' fp.txt)
	impl=$(awk -v p="$2" '$2 == p { print $8 }' fp.policies)
	if [ -n "$bit" ] && [ -n "$impl" ] &&
	    [ $(((flags >> bit) & 1)) -eq 1 ] &&
	    [ $(((impl >> bit) & 1)) -eq 1 ]; then
		echo yes
	else
		echo no
	fi
}

# entry_case name hook "command" oes-expected abac-expected
# expected: "yes" (the policy's hook runs) or "no".
entry_check()
{
	local hook=$1 cmd=$2 want_oes=$3 want_abac=$4

	require_dtrace
	if sysctl -n security.mac.fastpath > fp.txt 2>/dev/null; then
		# The framework is entered for a hook iff its flag is set,
		# and then calls every policy that implements the hook.
		want_oes=$(fp_expect_called $hook oes)
		want_abac=$(fp_expect_called $hook mac_abac)
		echo "$hook: expect oes $want_oes, mac_abac $want_abac"
	fi
	hooks_called "$cmd"
	if called "$hook" oes; then got=yes; else got=no; fi
	[ "$got" = "$want_oes" ] ||
	    atf_fail "oes $hook reached: $got, expected $want_oes"
	if called "$hook" mac_abac; then got=yes; else got=no; fi
	[ "$got" = "$want_abac" ] ||
	    atf_fail "mac_abac $hook reached: $got, expected $want_abac"
}

# Whether OES and mac_abac are reached with nobody listening, as the
# kernel under test must answer: "yes yes" before the idle gates; OES
# counts its fast-path hooks only while live from commit O3 on, mac_abac
# from A4 on.  With security.mac.fastpath the expectation is computed.
# Hooks both implement are reached by both while either counts the flag
# (an idle policy is still called, and returns at its gate); hooks only OES
# implements are reached only while OES counts them.
: ${SHARED_IDLE_ENTRY:=no}
: ${OES_ONLY_IDLE_ENTRY:=no}
: ${FP_INACTIVE_POLICIES:=oes mac_abac}

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
	    "/bin/cat /etc/passwd /etc/group" \
	    $SHARED_IDLE_ENTRY $SHARED_IDLE_ENTRY
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
	    "/bin/cat /etc/passwd /etc/group" \
	    $SHARED_IDLE_ENTRY $SHARED_IDLE_ENTRY
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
	    "/bin/cat /etc/passwd /etc/group" $OES_ONLY_IDLE_ENTRY no
	entry_check file_notify_close \
	    "/bin/cat /etc/passwd /etc/group" $OES_ONLY_IDLE_ENTRY no
}

# The security.mac.fastpath snapshot (see mac_framework.c), saved in fp.txt.
fp_snapshot()
{
	sysctl -n security.mac.fastpath > fp.txt ||
	    atf_fail "security.mac.fastpath is not readable"
	awk '/^hook /' fp.txt > fp.hooks
	awk '/^policy /' fp.txt > fp.policies
	[ -s fp.hooks ] && [ -s fp.policies ] ||
	    atf_fail "malformed snapshot: $(cat fp.txt)"
}

fp_flags()
{
	awk '/^flags / { print $2 }' fp.txt
}

# fp_bit hook: the hook's bit number (its line among the hook lines).
fp_bit()
{
	awk -v h="$1" '$2 == h { print NR - 1; f = 1 } END { exit !f }' \
	    fp.hooks || atf_fail "no hook $1 in the snapshot"
}

# fp_policy_field policy field: "inactive", "active" or "implemented".
fp_policy_field()
{
	awk -v p="$1" -v f="$2" '$2 == p {
		for (i = 3; i < NF; i += 2) if ($i == f) print $(i + 1)
		found = 1
	} END { exit !found }' fp.policies || atf_fail "no policy $1"
}

# fp_check_invariants: flags is the OR of every policy's active set, each
# count is the number of policies counting that hook, and no policy counts
# a hook it does not implement.
fp_check_invariants()
{
	local or flags a impl name cnt bit n

	or=0
	while read -r _ name _ _ _ a _ impl; do
		or=$((or | a))
		[ $((a & ~impl)) -eq 0 ] ||
		    atf_fail "policy $name counts unimplemented hooks: $a/$impl"
	done < fp.policies
	flags=$(fp_flags)
	[ $((flags)) -eq $or ] ||
	    atf_fail "flags $flags is not the OR of the policies ($(printf \
	    '0x%016x' $or))"
	bit=0
	while read -r _ name _ cnt; do
		n=0
		while read -r _ _ _ _ _ a _ _; do
			[ $(((a >> bit) & 1)) -eq 1 ] && n=$((n + 1))
		done < fp.policies
		[ $n -eq $cnt ] ||
		    atf_fail "hook $name: count $cnt, $n policies count it"
		[ $(((flags >> bit) & 1)) -eq $((cnt > 0)) ] ||
		    atf_fail "hook $name: count $cnt, flag $(((flags >> bit) & 1))"
		bit=$((bit + 1))
	done < fp.hooks
}

atf_test_case f1_snapshot_invariants
f1_snapshot_invariants_head()
{
	atf_set descr "F-1: security.mac.fastpath is self-consistent"
	atf_set require.user root
}
f1_snapshot_invariants_body()
{
	fp_snapshot
	cat fp.txt
	fp_check_invariants
}

atf_test_case f2_lockless_lookup_export
f2_lockless_lookup_export_head()
{
	atf_set descr "F-2: vfs.cache.param.fast_lookup_active follows the" \
	    "knob and the lookup and readlink fast-path flags"
	atf_set require.user root
}
f2_lockless_lookup_export_body()
{
	local active knob flags lk rl want

	fp_snapshot
	active=$(sysctl -n vfs.cache.param.fast_lookup_active) ||
	    atf_fail "vfs.cache.param.fast_lookup_active is not readable"
	knob=$(sysctl -n vfs.cache.param.fast_lookup)
	flags=$(fp_flags)
	lk=$(((flags >> $(fp_bit vnode_check_lookup)) & 1))
	rl=$(((flags >> $(fp_bit vnode_check_readlink)) & 1))
	want=0
	[ "$knob" -eq 1 ] && [ $lk -eq 0 ] && [ $rl -eq 0 ] && want=1
	echo "knob $knob lookup $lk readlink $rl active $active"
	[ "$active" -eq $want ] ||
	    atf_fail "fast_lookup_active $active, expected $want"
}

atf_test_case f3_new_flags
f3_new_flags_head()
{
	atf_set descr "F-3: close, pipe write and socket I/O have fast-path flags"
	atf_set require.user root
}
f3_new_flags_body()
{
	local h

	fp_snapshot
	for h in file_notify_close vnode_check_close pipe_check_write \
	    socket_check_send socket_check_receive socket_check_poll \
	    socket_check_stat; do
		fp_bit $h >/dev/null
	done
}

atf_test_case f4_inactive_policies
f4_inactive_policies_head()
{
	atf_set descr "F-4: oes and mac_abac register fast-path inactive and count"\
	    "nothing while nobody listens and no rule is loaded"
	atf_set require.user root
}
f4_inactive_policies_body()
{
	local p

	fp_snapshot
	for p in $FP_INACTIVE_POLICIES; do
		[ "$(fp_policy_field $p inactive)" = 1 ] ||
		    atf_fail "policy $p is not fast-path inactive"
		[ $(($(fp_policy_field $p active))) -eq 0 ] ||
		    atf_fail "policy $p counts $(fp_policy_field $p active)"
	done
}

atf_test_case abac_no_allow_stubs
abac_no_allow_stubs_head()
{
	atf_set descr "mac_abac implements no fast-path hook that allows in"\
	    "every case"
	atf_set require.user root
}
abac_no_allow_stubs_body()
{
	local h impl

	fp_snapshot
	impl=$(fp_policy_field mac_abac implemented)
	for h in priv_check priv_grant pipe_check_poll socket_check_poll \
	    socket_check_stat; do
		[ $(((impl >> $(fp_bit $h)) & 1)) -eq 0 ] ||
		    atf_fail "mac_abac implements $h"
	done
}

atf_init_test_cases()
{
	atf_add_test_case abac_no_allow_stubs
	atf_add_test_case f4_inactive_policies
	atf_add_test_case f3_new_flags
	atf_add_test_case f1_snapshot_invariants
	atf_add_test_case f2_lockless_lookup_export
	atf_add_test_case pin_lookup_walk
	atf_add_test_case entry_file_read
	atf_add_test_case entry_pipe_write
	atf_add_test_case entry_close
}
