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
	    event-deadline reply-late attach resolve-post resolve-reply; do
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

atf_init_test_cases()
{
	atf_add_test_case dq_probes_present
	atf_add_test_case dq_probes_fire
	atf_add_test_case mac_file_notify_reply_present
}
