#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# anoint(1) command-line contract, no capability plane needed: argument
# parsing, client-side name validation, and the "no session channel" fail-fast
# (E6).  Every case runs with SERVICE_LOOKUP_FD unset, the fixed-fd carry
# (fd 3) closed and stdin on /dev/null, so nothing can reach an agent and
# nothing can prompt; the assertion on stderr is EXACT so any "Password:"
# would fail it.  The elevated happy path needs a plane: see
# usr.sbin/BSDAuth/tests/elevate_integration_test.
#

USAGE="usage: anoint [-n] name command [argument ...]\n"

# Run anoint with no reachable session: env unset, fd 3 closed, no tty.
# atf_check execs its command directly (no shell functions), so this is a
# command string used as `sh -c "$NC" anoint ARG...`; arguments pass through
# verbatim, empty ones included.
NC='unset SERVICE_LOOKUP_FD; exec 3<&- 3>&-; exec anoint "$@" </dev/null'

# Locate anoint(1): $ANOINT (an object-tree binary for in-tree runs), else
# PATH (the installed /usr/bin/anoint on a guest); skip when neither.
require_anoint()
{
	if [ -n "${ANOINT:-}" ] && [ -x "${ANOINT}" ]; then
		PATH="$(dirname "${ANOINT}"):${PATH}"
		export PATH
	fi
	command -v anoint >/dev/null 2>&1 || atf_skip "anoint(1) not installed"
}

name_of_length() {
	# "a." followed by ($1 - 2) zeros: syntactically valid, length $1.
	printf 'a.%0*d' "$(($1 - 2))" 0
}

atf_test_case usage_no_args
usage_no_args_head() {
	atf_set "descr" "No arguments: usage on stderr, exit 1, no prompt"
}
usage_no_args_body() {
	require_anoint
	atf_check -s exit:1 -o empty -e inline:"$USAGE" sh -c "$NC" anoint
}

atf_test_case usage_name_only
usage_name_only_head() {
	atf_set "descr" "NAME without CMD is a usage error, before any name check"
}
usage_name_only_body() {
	require_anoint
	atf_check -s exit:1 -o empty -e inline:"$USAGE" \
	    sh -c "$NC" anoint org.example.x
	# ...even for an invalid name: argument count is checked first.
	atf_check -s exit:1 -o empty -e inline:"$USAGE" sh -c "$NC" anoint '*'
	atf_check -s exit:1 -o empty -e inline:"$USAGE" sh -c "$NC" anoint ''
	# -n consumes no operand: "-n NAME" alone is still short one.
	atf_check -s exit:1 -o empty -e inline:"$USAGE" \
	    sh -c "$NC" anoint -n org.example.x
	atf_check -s exit:1 -o empty -e inline:"$USAGE" sh -c "$NC" anoint -n
}

atf_test_case usage_unknown_option
usage_unknown_option_head() {
	atf_set "descr" "An unknown option is diagnosed by getopt then usage"
}
usage_unknown_option_body() {
	require_anoint
	atf_check -s exit:1 -o empty \
	    -e inline:"anoint: illegal option -- x\n$USAGE" \
	    sh -c "$NC" anoint -x org.example.x true
	atf_check -s exit:1 -o empty \
	    -e inline:"anoint: illegal option -- u\n$USAGE" \
	    sh -c "$NC" anoint -u root true
	# A combined cluster with a bad letter.
	atf_check -s exit:1 -o empty \
	    -e inline:"anoint: illegal option -- v\n$USAGE" \
	    sh -c "$NC" anoint -nv org.example.x true
}

atf_test_case name_star_rejected
name_star_rejected_head() {
	atf_set "descr" "'*' is a policy wildcard, never a requestable name"
}
name_star_rejected_body() {
	require_anoint
	atf_check -s exit:1 -o empty \
	    -e inline:"anoint: *: not an anointment name\n" \
	    sh -c "$NC" anoint -n '*' true
	atf_check -s exit:1 -o empty \
	    -e inline:"anoint: system.*: not an anointment name\n" \
	    sh -c "$NC" anoint -n 'system.*' true
}

atf_test_case name_nodot_rejected
name_nodot_rejected_body() {
	require_anoint
	atf_check -s exit:1 -o empty \
	    -e inline:"anoint: nodot: not an anointment name\n" \
	    sh -c "$NC" anoint -n nodot true
	atf_check -s exit:1 -o empty \
	    -e inline:"anoint: root: not an anointment name\n" \
	    sh -c "$NC" anoint -n root true
}

atf_test_case name_empty_rejected
name_empty_rejected_body() {
	require_anoint
	atf_check -s exit:1 -o empty \
	    -e inline:"anoint: : not an anointment name\n" \
	    sh -c "$NC" anoint -n '' true
}

atf_test_case name_dots_rejected
name_dots_rejected_head() {
	atf_set "descr" "Leading, trailing and doubled dots are refused"
}
name_dots_rejected_body() {
	require_anoint
	for n in .a.b a.b. a..b . .. ...; do
		atf_check -s exit:1 -o empty \
		    -e inline:"anoint: $n: not an anointment name\n" \
		    sh -c "$NC" anoint -n "$n" true
	done
}

atf_test_case name_bad_chars_rejected
name_bad_chars_rejected_body() {
	require_anoint
	for n in 'a.b c' a.b/c a.b:c a.b@c 'a.b!' 'a.b?' a.b,c; do
		atf_check -s exit:1 -o empty \
		    -e inline:"anoint: $n: not an anointment name\n" \
		    sh -c "$NC" anoint -n "$n" true
	done
}

atf_test_case name_64_chars_rejected
name_64_chars_rejected_head() {
	atf_set "descr" "A 64-character name (AUTHAGENT_NAME_MAX) is refused"
}
name_64_chars_rejected_body() {
	require_anoint
	n=$(name_of_length 64)
	atf_check -s exit:1 -o empty \
	    -e inline:"anoint: $n: not an anointment name\n" \
	    sh -c "$NC" anoint -n "$n" true
	n=$(name_of_length 65)
	atf_check -s exit:1 -o empty \
	    -e inline:"anoint: $n: not an anointment name\n" \
	    sh -c "$NC" anoint -n "$n" true
	n=$(name_of_length 300)
	atf_check -s exit:1 -o empty \
	    -e inline:"anoint: $n: not an anointment name\n" \
	    sh -c "$NC" anoint -n "$n" true
}

atf_test_case name_63_chars_passes_name_check
name_63_chars_passes_name_check_head() {
	atf_set "descr" "A 63-character name passes the name check (fails later on reach)"
}
name_63_chars_passes_name_check_body() {
	require_anoint
	n=$(name_of_length 63)
	atf_check -s exit:1 -o empty \
	    -e inline:"anoint: no session channel\n" \
	    sh -c "$NC" anoint -n "$n" true
	# Uppercase and the legal punctuation pass too.
	atf_check -s exit:1 -o empty \
	    -e inline:"anoint: no session channel\n" \
	    sh -c "$NC" anoint -n 'Org-1.Sub_2.X' true
}

atf_test_case no_session_channel_no_prompt
no_session_channel_no_prompt_head() {
	atf_set "descr" "Without an ambient channel: 'no session channel', exit 1, and NO password prompt"
}
no_session_channel_no_prompt_body() {
	require_anoint
	# Without -n the program would prompt -- but the channel check comes
	# first, and the EXACT stderr shows no "Password:" was ever written.
	atf_check -s exit:1 -o empty \
	    -e inline:"anoint: no session channel\n" \
	    sh -c "$NC" anoint org.example.x true
	atf_check -s exit:1 -o empty \
	    -e inline:"anoint: no session channel\n" \
	    sh -c "$NC" anoint -n org.example.x true
}

atf_test_case no_session_channel_precedes_exec
no_session_channel_precedes_exec_head() {
	atf_set "descr" "A missing CMD is not diagnosed when there is no channel (channel check precedes exec)"
}
no_session_channel_precedes_exec_body() {
	require_anoint
	atf_check -s exit:1 -o empty \
	    -e inline:"anoint: no session channel\n" \
	    sh -c "$NC" anoint org.example.x /nonexistent/definitely-not-here
	atf_check -s exit:1 -o empty \
	    -e inline:"anoint: no session channel\n" \
	    sh -c "$NC" anoint -n org.example.x no-such-command-xyzzy --flag
	# And not exit 126/127, which would mean exec was attempted.
	atf_check -s not-exit:127 -o empty -e ignore \
	    sh -c "$NC" anoint -n org.example.x no-such-command-xyzzy
	atf_check -s not-exit:126 -o empty -e ignore \
	    sh -c "$NC" anoint -n org.example.x /etc/passwd
}

atf_test_case name_check_precedes_channel_check
name_check_precedes_channel_check_head() {
	atf_set "descr" "A bad name is refused before the channel is looked for"
}
name_check_precedes_channel_check_body() {
	require_anoint
	atf_check -s exit:1 -o empty \
	    -e inline:"anoint: nodot: not an anointment name\n" \
	    sh -c "$NC" anoint nodot /nonexistent/cmd
}

atf_test_case bogus_lookup_fd_env
bogus_lookup_fd_env_head() {
	atf_set "descr" "SERVICE_LOOKUP_FD that is not a live channel fd is 'no session channel'"
}
bogus_lookup_fd_env_body() {
	require_anoint
	for v in notanumber -1 '' 99999 3 0 1 2 '3x' ' 3' 2147483648; do
		atf_check -s exit:1 -o empty \
		    -e inline:"anoint: no session channel\n" \
		    sh -c 'export SERVICE_LOOKUP_FD="$1"; exec 3</dev/null; \
			exec anoint -n org.example.x true </dev/null' sh "$v"
	done
	# fd 3 open on a regular file is not a channel either.
	atf_check -s exit:1 -o empty \
	    -e inline:"anoint: no session channel\n" \
	    sh -c 'unset SERVICE_LOOKUP_FD; exec 3</etc/passwd; \
		exec anoint -n org.example.x true </dev/null'
	atf_check -s exit:1 -o empty \
	    -e inline:"anoint: no session channel\n" \
	    sh -c 'unset SERVICE_LOOKUP_FD; exec 3<>/dev/null; \
		exec anoint org.example.x true </dev/null'
}

atf_test_case option_end_marker
option_end_marker_head() {
	atf_set "descr" "'--' ends options; a name starting with '-' is then checked as a name"
}
option_end_marker_body() {
	require_anoint
	atf_check -s exit:1 -o empty \
	    -e inline:"anoint: no session channel\n" \
	    sh -c "$NC" anoint -- -a.b true
	atf_check -s exit:1 -o empty \
	    -e inline:"anoint: -nodot: not an anointment name\n" \
	    sh -c "$NC" anoint -- -nodot true
}

atf_init_test_cases() {
	atf_add_test_case usage_no_args
	atf_add_test_case usage_name_only
	atf_add_test_case usage_unknown_option
	atf_add_test_case name_star_rejected
	atf_add_test_case name_nodot_rejected
	atf_add_test_case name_empty_rejected
	atf_add_test_case name_dots_rejected
	atf_add_test_case name_bad_chars_rejected
	atf_add_test_case name_64_chars_rejected
	atf_add_test_case name_63_chars_passes_name_check
	atf_add_test_case no_session_channel_no_prompt
	atf_add_test_case no_session_channel_precedes_exec
	atf_add_test_case name_check_precedes_channel_check
	atf_add_test_case bogus_lookup_fd_env
	atf_add_test_case option_end_marker
}
