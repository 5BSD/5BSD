#!/usr/bin/env atf-sh

setup()
{
	mkdir -p root/etc root/var/db root/boot state boot-state bin scratch
	export TEST_CALLS="$(pwd)/calls"
	cat >bin/bsdinstall <<-'EOF'
	#!/bin/sh
	printf '%s\n' "$*" >>"${TEST_CALLS}"
	[ "$1" != pkgbase ] || [ "${TEST_FAIL:-}" != yes ] || exit 1
	EOF
	cat >bin/bsddialog <<-'EOF'
	#!/bin/sh
	echo UNEXPECTED_DIALOG >>"${TEST_CALLS}"
	exit 1
	EOF
	chmod +x bin/*
}

run_jail()
{
	env PATH="$(pwd)/bin:/bin:/usr/bin:/sbin:/usr/sbin" \
	    nonInteractive=YES SCRIPT= TMPDIR="$(pwd)/scratch" \
	    BSDINSTALL_TMPETC="$(pwd)/state" \
	    BSDINSTALL_TMPBOOT="$(pwd)/boot-state" \
	    sh @SRCTOP@/usr.sbin/bsdinstall/scripts/jail "$(pwd)/root"
}

atf_test_case unattended_pkgbase
unattended_pkgbase_body()
{
	setup
	run_jail >output 2>errors || atf_fail 'unattended jail installation failed'
	atf_check -s exit:0 -o ignore grep -Fx 'pkgbase --jail --non-interactive' calls
	atf_check -s exit:1 -o empty grep UNEXPECTED_DIALOG calls
}

atf_test_case unattended_failure
unattended_failure_body()
{
	setup
	export TEST_FAIL=yes
	if run_jail >output 2>errors; then
		atf_fail 'failed pkgbase reported success'
	fi
	atf_check -s exit:0 -o ignore grep -F 'Installation of base system packages failed' errors
	atf_check -s exit:1 -o empty grep UNEXPECTED_DIALOG calls
	atf_check -s exit:1 -o empty grep '^config$' calls
}

atf_init_test_cases()
{
	atf_add_test_case unattended_pkgbase
	atf_add_test_case unattended_failure
}
