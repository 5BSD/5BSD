#
# SPDX-License-Identifier: BSD-2-Clause
#
# The DescriptorQueue registers its DTrace provider (dq_dev.c): one probe per
# queue open and close, mint, revoke and object close, and one per step of an
# event's life (post, deliver, reply, drop, interrupt, deadline, late reply).
# The MAC framework gains the file_notify_reply hook the reply path calls,
# visible as a mac_framework probe pair like every other hook.
#

atf_test_case dq_probes_present
dq_probes_present_head()
{
	atf_set "descr" "every dq provider probe is registered"
	atf_set "require.user" "root"
	atf_set "require.progs" "dtrace"
}
dq_probes_present_body()
{
	[ -c /dev/dq ] || atf_skip "/dev/dq is absent"
	# Under the plane a late kldload is denied: no dtrace modules, no list.
	dtrace -l >/dev/null 2>dtrace.err || atf_skip "dtrace -l: 1001 0 20 43 44 145 1001cat dtrace.err)"
	atf_check -o save:dq dtrace -l -P dq
	for probe in queue-open queue-close mint revoke object-close \
	    event-post event-deliver event-reply event-drop event-interrupt \
	    event-deadline reply-late; do
		atf_check -o ignore grep -q " ${probe}\$" dq
	done
}

atf_test_case mac_file_notify_reply_present
mac_file_notify_reply_present_head()
{
	atf_set "descr" "mac_framework exposes the file_notify_reply hook"
	atf_set "require.user" "root"
	atf_set "require.progs" "dtrace"
}
mac_file_notify_reply_present_body()
{
	[ -c /dev/dq ] || atf_skip "/dev/dq is absent"
	dtrace -l >/dev/null 2>dtrace.err || atf_skip "dtrace -l: 1001 0 20 43 44 145 1001cat dtrace.err)"
	atf_check -o save:mac dtrace -l -P mac_framework
	atf_check -o ignore grep -q 'file_notify_reply' mac
}

atf_init_test_cases()
{
	atf_add_test_case dq_probes_present
	atf_add_test_case mac_file_notify_reply_present
}
