#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#

atf_test_case security_scripts_compile
security_scripts_compile_head()
{
	atf_set descr "security DTrace scripts compile against installed providers"
	atf_set require.progs dtrace
	atf_set require.user root
}

providers_available()
{
	for provider in "$@"; do
		if ! dtrace -l -P "$provider" 2>/dev/null | awk 'NR > 1 { found = 1 } END { exit !found }'; then
			return 1
		fi
	done
	return 0
}

compile_script()
{
	name=$1
	shift
	path="/usr/share/dtrace/$name"
	[ -f "$path" ] || atf_fail "missing installed script: $path"
	if [ "$#" -gt 0 ] && ! providers_available "$@"; then
		echo "skipping $name: matching kernel providers are not loaded"
		return
	fi
	atf_check -s exit:0 -o empty -e empty dtrace -Z -e -s "$path"
}

security_scripts_compile_body()
{
	compile_script authwatch
	compile_script capwatch capsicum
	compile_script casper-mediation
	compile_script container-escape jail mount vfs capsicum ptrace
	compile_script daemon-exec
	compile_script denials capsicum priv jail rctl pfil mac_framework vfs kld ptrace
	compile_script fileless-exec shmfd vm sysvshm imgact
	compile_script pam-stack
	compile_script privesc cred priv jail
	compile_script secreport
	compile_script sessions
	compile_script vmm-passthru
	compile_script mac_capability-delegation
	compile_script mac_capability-messages
}

atf_init_test_cases()
{
	atf_add_test_case security_scripts_compile
}
