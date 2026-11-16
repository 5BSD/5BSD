#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# The descriptor-operations layer registers its DTrace probes: a default
# answering for a table without the member (fd:::invfo), a system call
# refusing a descriptor before looking at its arguments (fd:::refused), and
# the construction and close of an exec image source
# (proc:::exec-image-open, proc:::exec-image-close).
#

atf_test_case probes_present
probes_present_head()
{
	atf_set "descr" "fd:::invfo, fd:::refused and proc:::exec-image-* are registered"
	atf_set "require.user" "root"
	atf_set "require.progs" "dtrace"
}
probes_present_body()
{
	atf_check -o save:fd dtrace -l -P fd
	atf_check -o ignore grep -q ' invfo$' fd
	atf_check -o ignore grep -q ' refused$' fd
	atf_check -o save:proc dtrace -l -P proc
	atf_check -o ignore grep -q ' exec-image-open$' proc
	atf_check -o ignore grep -q ' exec-image-close$' proc
}

atf_init_test_cases()
{
	atf_add_test_case probes_present
}
