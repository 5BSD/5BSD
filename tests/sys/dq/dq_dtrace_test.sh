#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# The DescriptorQueue registers its DTrace provider (dq_dev.c): one probe per
# queue open and close, mint, revoke and object close, and one per step of an
# event's life (post, deliver, reply, drop, interrupt, deadline, late reply).
# The MAC framework gains the file_notify_reply hook the reply path calls,
# visible as a mac_framework probe pair like every other hook.
#
# Under the capability plane a module load after boot is refused, so the
# DTrace modules must be preloaded (dtraceall_load="YES" in loader.conf).
# Without them these cases fail: a skip in a plane-on run is not a pass.
#

# Fail unless the queue device and DTrace are there.
require_dtrace()
{
	[ -c /dev/dq ] || atf_fail "/dev/dq is absent"
	dtrace -l >/dev/null 2>dtrace.err ||
	    atf_fail "dtrace -l: $(cat dtrace.err) (preload dtraceall)"
}

# usage: fire PROBE FORMAT ARGS PROGRAM CASE
# Run one case of a C test program of this directory under DTrace, with
# PROBE printing FORMAT of ARGS for every firing in the case's progeny,
# into the file "fired"; the case must pass.  A case with a cleanup part
# has it run after.
fire()
{
	local probe fmt args prog tc

	probe="$1"; fmt="$2"; args="$3"; prog="$4"; tc="$5"
	printf '%s -r result %s\n' "$(atf_get_srcdir)/${prog}" "${tc}" > run.sh
	printf '%s -r cleanup %s:cleanup\n' "$(atf_get_srcdir)/${prog}" \
	    "${tc}" >> run.sh
	atf_check -o save:fired -e ignore dtrace -q -n "
	    ${probe} /progenyof(\$target)/ { printf(\"${fmt}\\n\", ${args}); }" \
	    -c "/bin/sh run.sh"
	grep -q '^passed' result ||
	    atf_fail "${prog}:${tc} under DTrace: $(cat result)"
}

atf_test_case dq_probes_present
dq_probes_present_head()
{
	atf_set "descr" "every dq provider probe is registered"
	atf_set "require.user" "root"
}
dq_probes_present_body()
{
	require_dtrace
	for probe in queue-open queue-close mint revoke object-close \
	    event-post event-deliver event-reply event-drop event-interrupt \
	    event-deadline reply-late attach resolve-post resolve-reply \
	    fop-local quota-wait postop-attr; do
		atf_check -o ignore dtrace -l -n "dq:::${probe}"
	done
}

atf_test_case dq_probes_fire
dq_probes_fire_head()
{
	atf_set "descr" "the dq probes fire for dqpass's own queue: it opens " \
	    "a queue, attaches a command whose lookups are posted and " \
	    "answered, and closes it, and dqpass itself exits 0"
	atf_set "require.user" "root"
}
dq_probes_fire_body()
{
	require_dtrace
	# The traced command is a shell running dqpass: every probe counted
	# is in that shell's progeny (dqpass, its attached command), never
	# in Capsule's, SwitchBoard's or another supervisor's queue.  The
	# shell records dqpass's exit status.  (dtrace -c splits its command
	# on blanks, so the shell reads a script.)
	printf '%s -o report /bin/test -e /\necho $? > status\n' \
	    "$(atf_get_srcdir)/dqpass" > run.sh
	atf_check -o save:fired -e ignore dtrace -q -n '
	    dq:::queue-open, dq:::queue-close, dq:::attach,
	    dq:::resolve-post, dq:::resolve-reply
	    /progenyof($target)/
	    { @n[probename] = count(); }
	    END { printa("%s %@d\n", @n); }' \
	    -c "/bin/sh run.sh"
	atf_check -o inline:"0\n" cat status
	for probe in queue-open queue-close attach resolve-post \
	    resolve-reply; do
		atf_check -o ignore grep -Eq "^${probe} [1-9][0-9]*\$" fired
	done
}

atf_test_case mac_file_notify_reply_present
mac_file_notify_reply_present_head()
{
	atf_set "descr" "mac_framework exposes the file_notify_reply hook"
	atf_set "require.user" "root"
}
mac_file_notify_reply_present_body()
{
	require_dtrace
	for name in mac-check-ok mac-check-err; do
		atf_check -o ignore \
		    dtrace -l -n "mac_framework::file_notify_reply:${name}"
	done
}

atf_test_case fop_local_fires
fop_local_fires_head()
{
	atf_set "descr" "dq:::fop-local fires for the fileops a served " \
	    "directory answers locally, with the operation and errno"
	atf_set "require.user" "root"
}
fop_local_fires_body()
{
	require_dtrace
	fire dq:::fop-local "%d %d" "arg1, arg2" dq_stage1a_test \
	    dir_local_answers
	# posix_fadvise (3) ENODEV (19), FIOSEEKDATA (1) ENOTTY (25),
	# F_READAHEAD (2) ENOTTY.
	atf_check -o ignore grep -qx '3 19' fired
	atf_check -o ignore grep -qx '1 25' fired
	atf_check -o ignore grep -qx '2 25' fired
}

atf_test_case namei_served_fires
namei_served_fires_head()
{
	atf_set "descr" "dqres:::namei-served fires for a lookup from a " \
	    "served root, with the operation, the answer kind and errno"
	atf_set "require.user" "root"
}
namei_served_fires_body()
{
	require_dtrace
	fire dqres:::namei-served "%d %d %d" "arg0, arg1, arg2" \
	    dq_identity_test stat_gen_unpriv
	# stat(2) (DQ_ROP_STAT 2) answered ATTR (3), no error.
	atf_check -o ignore grep -qx '2 3 0' fired
}

atf_test_case quota_wait_fires
quota_wait_fires_head()
{
	atf_set "descr" "dq:::quota-wait fires when a wait for the " \
	    "requester's in-flight quota reaches the event's deadline"
	atf_set "require.user" "root"
}
quota_wait_fires_body()
{
	require_dtrace
	fire dq:::quota-wait "%d %d" "arg2, arg3" dq_deadline_test \
	    quota_requester_bounded
	# The requester's quota (2), EIO (5).
	atf_check -o ignore grep -qx '2 5' fired
}

atf_test_case subst_fires
subst_fires_head()
{
	atf_set "descr" "dqres:::subst-refuse, subst-install and " \
	    "subst-consume fire for a refused and an accepted substitute"
	atf_set "require.user" "root"
}
subst_fires_body()
{
	require_dtrace
	# A substitute that was read from: refused at the take for an open
	# (DQ_ROP_OPEN 1), reason 23 (its offset), EFTYPE (79).
	fire dqres:::subst-refuse "%d %d %d" "arg0, arg1, arg2" \
	    dq_swap_test swap_offset_carried
	atf_check -o ignore grep -qx '1 23 79' fired
	# An accepted one: the supervisor's descriptor is closed with the
	# take, and the program's installed.
	fire dqres:::subst-consume "consume %d" "arg1" dq_swap_test \
	    swap_regular
	atf_check -o ignore grep -Eqx 'consume [0-9]+' fired
	fire dqres:::subst-install "install %d %d" "arg0, arg1" dq_swap_test \
	    swap_regular
	atf_check -o ignore grep -Eqx 'install 1 [0-9]+' fired
}

atf_test_case present_fires
present_fires_head()
{
	atf_set "descr" "dqres:::present fires for the paths shown to a " \
	    "program under a served root: a real object's and a served one's"
	atf_set "require.user" "root"
}
present_fires_body()
{
	require_dtrace
	# A real object under a served root (2): no path, ENOENT (2).
	fire dqres:::present "%d %d" "arg1, arg2" dq_getcwd_test \
	    real_object_paths_served_root
	atf_check -o ignore grep -qx '2 2' fired
	# A served mapping's path (1), presented.
	fire dqres:::present "%d %d" "arg1, arg2" dq_mmap_test \
	    vmmap_path_served_root
	atf_check -o ignore grep -qx '1 0' fired
}

atf_test_case postop_attr_fires
postop_attr_fires_head()
{
	atf_set "descr" "dq:::postop-attr fires for an applied and an " \
	    "ignored post-operation block, with the op, the mask and errno"
	atf_set "require.user" "root"
}
postop_attr_fires_body()
{
	require_dtrace
	# A WRITE (3) with size, mtime and ctime (7): applied, then ignored.
	fire dq:::postop-attr "%d %d %d" "arg1, arg2, arg3" dq_write_test \
	    postop_size_larger_accepted
	atf_check -o ignore grep -qx '3 7 0' fired
	fire dq:::postop-attr "%d %d %d" "arg1, arg2, arg3" dq_write_test \
	    postop_size_smaller_ignored
	atf_check -o ignore grep -qx '3 7 22' fired
}

atf_init_test_cases()
{
	atf_add_test_case dq_probes_present
	atf_add_test_case dq_probes_fire
	atf_add_test_case mac_file_notify_reply_present
	atf_add_test_case fop_local_fires
	atf_add_test_case namei_served_fires
	atf_add_test_case quota_wait_fires
	atf_add_test_case subst_fires
	atf_add_test_case present_fires
	atf_add_test_case postop_attr_fires
}
