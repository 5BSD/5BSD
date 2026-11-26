#
# Copyright (c) 2017 Enji Cooper <ngie@FreeBSD.org>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
# ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#

PROG_PID=
PROG_PATH=$(atf_get_srcdir)/while1

SP='[[:space:]]'

start_program()
{
	echo "Starting program in background"
	PROG_COMM=while1
	PROG_PATH=$(atf_get_srcdir)/$PROG_COMM

	mkfifo wait_for_start || atf_fail "mkfifo"
	$PROG_PATH $* >wait_for_start &
	PROG_PID=$!
	if ! read dummy <wait_for_start; then
		atf_fail "Program did not start properly"
	fi
	rm wait_for_start
}

atf_test_case binary_info
binary_info_head()
{
	atf_set "descr" "Checks -b support"
}
binary_info_body()
{
	start_program bogus-arg

	line_format="$SP*%s$SP+%s$SP+%s$SP+%s$SP*"
	header_re=$(printf "$line_format" "PID" "COMM" "OSREL" "PATH")
	line_re=$(printf "$line_format" $PROG_PID $PROG_COMM "[[:digit:]]+" "$PROG_PATH")

	atf_check -o save:procstat.out procstat binary $PROG_PID
	atf_check -o match:"$header_re" head -n 1 procstat.out
	atf_check -o match:"$line_re" tail -n 1 procstat.out

	atf_check -o save:procstat.out procstat -b $PROG_PID
	atf_check -o match:"$header_re" head -n 1 procstat.out
	atf_check -o match:"$line_re" tail -n 1 procstat.out
}

atf_test_case binary_info_unsignalable cleanup
binary_info_unsignalable_head()
{
	atf_set "descr" "Binary metadata remains readable when signal permission is denied"
	atf_set "require.user" "root"
	atf_set "require.progs" "su procstat sysctl"
}
binary_info_unsignalable_body()
{
	[ "$(sysctl -n security.bsd.see_other_uids)" = 1 ] ||
	    atf_skip "System policy disables cross-UID process visibility"
	unprivileged_user=$(atf_config_get unprivileged_user nobody)
	id "${unprivileged_user}" >/dev/null 2>&1 ||
	    atf_skip "Unprivileged test account is unavailable"
	start_program
	echo "$PROG_PID" >program.pid

	# A different UID cannot signal the live root-owned child. Process
	# visibility is a separate policy: require it before exercising -b.
	atf_check -s exit:1 -e ignore su -m "${unprivileged_user}" \
	    -c "/bin/kill -0 $PROG_PID"
	atf_check -o save:visible.out su -m "${unprivileged_user}" \
	    -c "procstat -b $PROG_PID"
	read -r pid command osrel pathname <<EOF
$(tail -n 1 visible.out)
EOF
	atf_check_equal "$pid" "$PROG_PID"
	atf_check_equal "$command" "$PROG_COMM"
	atf_check_equal "$pathname" "$PROG_PATH"
}
binary_info_unsignalable_cleanup()
{
	if [ -f program.pid ]; then
		kill "$(cat program.pid)" 2>/dev/null || :
	fi
}

atf_test_case command_line_arguments
command_line_arguments_head()
{
	atf_set "descr" "Checks -c support"
}
command_line_arguments_body()
{
	arguments="my arguments"

	start_program $arguments

	line_format="$SP*%s$SP+%s$SP+%s$SP*"
	header_re=$(printf "$line_format" "PID" "COMM" "ARGS")
	line_re=$(printf "$line_format" $PROG_PID "$PROG_COMM" "$PROG_PATH $arguments")

	atf_check -o save:procstat.out procstat arguments $PROG_PID
	atf_check -o match:"$header_re" head -n 1 procstat.out
	atf_check -o match:"$line_re" tail -n 1 procstat.out

	atf_check -o save:procstat.out procstat -c $PROG_PID
	atf_check -o match:"$header_re" head -n 1 procstat.out
	atf_check -o match:"$line_re" tail -n 1 procstat.out
}

atf_test_case environment
environment_head()
{
	atf_set "descr" "Checks -e support"
}
environment_body()
{
	var="MY_VARIABLE=foo"
	eval "export $var"

	start_program my arguments

	line_format="$SP*%s$SP+%s$SP+%s$SP*"
	header_re=$(printf "$line_format" "PID" "COMM" "ENVIRONMENT")
	line_re=$(printf "$line_format" $PROG_PID $PROG_COMM ".*$var.*")

	atf_check -o save:procstat.out procstat environment $PROG_PID
	atf_check -o match:"$header_re" head -n 1 procstat.out
	atf_check -o match:"$line_re" tail -n 1 procstat.out

	atf_check -o save:procstat.out procstat -e $PROG_PID
	atf_check -o match:"$header_re" head -n 1 procstat.out
	atf_check -o match:"$line_re" tail -n 1 procstat.out
}

atf_test_case file_descriptor
file_descriptor_head()
{
	atf_set "descr" "Checks -f support"
}
file_descriptor_body()
{
	start_program my arguments

	line_format="$SP*%s$SP+%s$SP+%s$SP+%s$SP+%s$SP+%s$SP+%s$SP+%s$SP+%s$SP%s$SP*"
	header_re=$(printf "$line_format" "PID" "COMM" "FD" "T" "V" "FLAGS" "REF" "OFFSET" "PRO" "NAME")
	# XXX: write a more sensible feature test
	line_re=$(printf "$line_format" $PROG_PID $PROG_COMM ".+" ".+" ".+" ".+" ".+" ".+" ".+" ".+")

	atf_check -o save:procstat.out procstat files $PROG_PID
	atf_check -o match:"$header_re" head -n 1 procstat.out
	atf_check -o match:"$line_re" awk 'NR > 1' procstat.out

	atf_check -o save:procstat.out procstat -f $PROG_PID
	atf_check -o match:"$header_re" head -n 1 procstat.out
	atf_check -o match:"$line_re" awk 'NR > 1' procstat.out
}

atf_test_case kernel_stacks
kernel_stacks_head()
{
	atf_set "descr" "Captures kernel stacks for all visible threads"
}
# With the capability plane on, mac_capability shields its protected
# processes (init, the capability services) from debugging: p_candebug()
# fails with EACCES, which libprocstat reports (it is silent only for
# FreeBSD's EPERM).  Those warnings are the only stderr allowed.
check_kstack_stderr()
{
	atf_check -s exit:1 grep -v -E \
	    '^procstat: sysctl: kern\.proc\.kstack: [0-9]+: Permission denied$' \
	    "$1"
}

kernel_stacks_body()
{
	atf_check -o save:procstat.out -e save:procstat.err procstat -a kstack
	check_kstack_stderr procstat.err
	atf_check -o not-empty awk '{if ($3 == "procstat") print}' procstat.out

	atf_check -o save:procstat.out -e save:procstat.err procstat -kka
	check_kstack_stderr procstat.err
	atf_check -o not-empty awk '{if ($3 == "procstat") print}' procstat.out
}

atf_test_case audit_token
audit_token_head()
{
	atf_set "descr" "procstat token and the ps keywords show the " \
	    "audit token ids from kinfo_proc"
	atf_set "require.progs" "ps"
}
audit_token_body()
{
	start_program bogus-arg

	header_re=$(printf "$SP*%s$SP+%s$SP+%s$SP+%s$SP+%s$SP*" \
	    PID COMM UNIQUEID EXECGEN IMAGEID)
	atf_check -o save:procstat.out procstat token $PROG_PID
	atf_check -o match:"$header_re" head -n 1 procstat.out
	set -- $(tail -n 1 procstat.out)
	[ "$1" = "$PROG_PID" ] || atf_fail "pid $1, wanted $PROG_PID"
	[ "$2" = "$PROG_COMM" ] || atf_fail "command $2"
	# ps(1) reads the same fields.
	atf_check -o inline:"$3 $4 $5\n" sh -c \
	    "ps -o uniqueid=,execgen=,imageid= -p $PROG_PID | awk '{print \$1, \$2, \$3}'"
	# Every id of an exec'd program is set.
	[ "$3" -gt 0 ] && [ "$4" -gt 0 ] && [ "$5" -gt 0 ] ||
	    atf_fail "unset id: $*"
	# The kernel's proc0 is the first process of the boot (its ids are
	# the boot's random offset plus one: low 32 bits 1) and has no image.
	set -- $(ps -o uniqueid=,execgen=,imageid= -p 0)
	[ $(($1 & 0xffffffff)) -eq 1 ] && [ $(($2 & 0xffffffff)) -eq 1 ] &&
	    [ "$3" = 0 ] || atf_fail "proc0 ids: $*"
}

atf_init_test_cases()
{
	atf_add_test_case audit_token
	atf_add_test_case binary_info
	atf_add_test_case binary_info_unsignalable
	atf_add_test_case command_line_arguments
	atf_add_test_case environment
	atf_add_test_case file_descriptor
	atf_add_test_case kernel_stacks
}
