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
# into the file "fired"; the case must pass.  A case that defers to
# another tier (a DEFERRED_* skip, such as dqt_require_plane()'s on a
# plane-off boot) defers this one the same way.  A case with a cleanup part
# has it run after.  Each run has a work directory of its own, as kyua
# gives each case.
fire()
{
	local probe fmt args prog tc

	probe="$1"; fmt="$2"; args="$3"; prog="$4"; tc="$5"
	rm -rf work
	mkdir work
	printf 'cd work\n' > run.sh
	printf '%s -r ../result %s\n' "$(atf_get_srcdir)/${prog}" "${tc}" >> run.sh
	printf '%s -r ../cleanup %s:cleanup\n' "$(atf_get_srcdir)/${prog}" \
	    "${tc}" >> run.sh
	atf_check -o save:fired -e ignore dtrace -q -n "
	    ${probe} /progenyof(\$target)/ { printf(\"${fmt}\\n\", ${args}); }" \
	    -c "/bin/sh run.sh"
	case $(cat result) in
	skipped:*DEFERRED_*)
		atf_skip "$(sed 's/^skipped: //' result) (${prog}:${tc})" ;;
	esac
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
	    fop-local quota-wait postop-attr wait-full wait-abandon \
	    standing-match standing-miss standing-change; do
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

atf_test_case standing_probes cleanup
standing_probes_head()
{
	atf_set "descr" "the standing-rule probes fire for dqpass -r: " \
	    "standing-match with the rule's id and PASS, standing-miss " \
	    "for no fitting rule, an ineligible lookup (an AF_UNIX " \
	    "connect, a Linux RINROOT open) and a '..' name, and " \
	    "standing-change at the rule's ADD and the queue's death"
	atf_set "require.user" "root"
	atf_set "require.kmods" "linux64"
	atf_set "require.arch" "amd64"
}
standing_probes_body()
{
	require_dtrace
	# The Linux program's lookups are native ones without an ABI root
	# (dq_standing_test rinroot_posts): only RINROOT makes it ineligible.
	sysctl -n compat.linux.emul_path > emul_path.saved ||
	    atf_fail "compat.linux.emul_path"
	atf_check -o ignore sysctl compat.linux.emul_path=/nonexistent-dq-standing
	mkdir lx
	touch lx/rin-f
	cp "$(atf_get_srcdir)/dq_standing_linux" . ||
	    atf_fail "dq_standing_linux is not installed"
	# The command: covered names, a name no rule fits, a '..' name,
	# an AF_UNIX connect and the Linux program (descriptor 9: lx).
	cat > cmd.sh <<'EOS'
test -d /usr/share/misc
test -d /etc
test -d /usr/share/../share
nc -lU sock > /dev/null & i=0
while [ ! -S sock ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
echo x | nc -NU sock
wait
./dq_standing_linux 9< lx
echo $? > linux.status
EOS
	printf '%s -o report -r /usr/share:read /bin/sh cmd.sh\necho $? > status\n' \
	    "$(atf_get_srcdir)/dqpass" > run.sh
	atf_check -o save:fired -e ignore dtrace -q -n '
	    dq:::standing-match /progenyof($target)/
	    { @m[arg2, arg3] = count(); }
	    dq:::standing-miss /progenyof($target)/
	    { @w[arg2] = count(); }
	    dq:::standing-change /progenyof($target)/
	    { @c[arg1, arg2] = count(); }
	    END {
		printa("match %d %d %@d\n", @m);
		printa("miss %d %@d\n", @w);
		printa("change %d %d %@d\n", @c);
	    }' -c "/bin/sh run.sh"
	cat fired report >&2
	atf_check -o inline:"0\n" cat status
	atf_check -o inline:"0\n" cat linux.status
	# The rule is the queue's first: id 1, verdict 0 (PASS).
	atf_check -o ignore grep -Eq '^match 1 0 [1-9][0-9]*$' fired
	# Why: 0 no rule fits (/etc), 1 ineligible (connect, RINROOT), 2 "..".
	for why in 0 1 2; do
		atf_check -o ignore grep -Eq "^miss ${why} [1-9][0-9]*\$" fired
	done
	# What: 1 ADD (id 1), 4 the queue's death.
	atf_check -o ignore grep -Eq '^change 1 1 1$' fired
	atf_check -o ignore grep -Eq '^change 4 0 1$' fired
	atf_check -o match:'standing pass [1-9]' cat report
}
standing_probes_cleanup()
{
	[ -s emul_path.saved ] &&
	    sysctl compat.linux.emul_path="$(cat emul_path.saved)" >/dev/null
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

atf_test_case wait_fires
wait_fires_head()
{
	atf_set "descr" "dq:::wait-full fires once per post that waited for a " \
	    "slot, with how it ended; dq:::wait-abandon for a wait a dying " \
	    "process left"
	atf_set "require.user" "root"
}
wait_fires_body()
{
	require_dtrace
	# A post that waited for the slot and then went on (0).
	fire dq:::wait-full "full %d" "arg2" dq_concurrency_test \
	    full_waits_then_posts
	atf_check -o ignore grep -qx 'full 0' fired
	# One that reached its deadline there (EIO, 5).
	fire dq:::wait-full "full %d" "arg2" dq_concurrency_test \
	    full_deadline_eio
	atf_check -o ignore grep -qx 'full 5' fired
	# A read with no deadline whose process exits.
	fire dq:::wait-abandon "abandon %d" "arg1 != 0" dq_read_test \
	    read_deadline0_exit_sibling
	atf_check -o ignore grep -qx 'abandon 1' fired
}

atf_test_case pager_error_reason
pager_error_reason_head()
{
	atf_set "descr" "dq:::pager-error fires at a failed page-in with " \
	    "its reason: the supervisor's error, the deadline, a dying " \
	    "process, a revoked object"
	atf_set "require.user" "root"
}
pager_error_reason_body()
{
	require_dtrace
	# Reasons (dq_pager.c): 1 deadline, 2 queue closing, 3 dying,
	# 4 revoked, 5 reply error, 6 object closed, 7 invalidated.
	fire dq:::pager-error "pager %d" "arg2" dq_mmap_test sigbus_cases
	atf_check -o ignore grep -qx 'pager 5' fired
	fire dq:::pager-error "pager %d" "arg2" dq_mmap_test sigbus_deadline
	atf_check -o ignore grep -qx 'pager 1' fired
	fire dq:::pager-error "pager %d" "arg2" dq_mmap_test \
	    fault_single_exit
	atf_check -o ignore grep -qx 'pager 3' fired
	fire dq:::pager-error "pager %d" "arg2" dq_mmap_test \
	    fork_mapping_revoke
	atf_check -o ignore grep -qx 'pager 4' fired
}

atf_init_test_cases()
{
	atf_add_test_case dq_probes_present
	atf_add_test_case dq_probes_fire
	atf_add_test_case standing_probes
	atf_add_test_case mac_file_notify_reply_present
	atf_add_test_case fop_local_fires
	atf_add_test_case namei_served_fires
	atf_add_test_case quota_wait_fires
	atf_add_test_case subst_fires
	atf_add_test_case present_fires
	atf_add_test_case postop_attr_fires
	atf_add_test_case wait_fires
	atf_add_test_case pager_error_reason
}
