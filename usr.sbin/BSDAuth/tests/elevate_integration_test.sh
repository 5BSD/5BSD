#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# Live-plane elevation tests (docs/book/src/plane/anointments.md, scenarios S6,
# P3-P5, P9, E1, E3, E6): drive anoint(1) against the running
# system.auth from a login session.  The success paths need a live
# switchboard to mint session-set-plus-one, so they are integration tests
# here rather than in the C provider test (whose fixture has no switchboard).
#
# These pass only on a live plane -- a session that inherited an ambient
# lookup channel -- with anoint(1) installed.  Off the plane (the build host,
# or any session without the channel) every case skips, following
# usr.sbin/switchboard/tests/service_reachability_test.sh.
#
# Password-driven cases (P3, P4, E1, E3) need a principal whose password the
# test knows.  They read it from the environment: set AUTHAGENT_TEST_USER and
# AUTHAGENT_TEST_PASSWORD (a local account in a principal entry with a
# may_elevate list that contains AUTHAGENT_TEST_NAME, default
# system.notify.system) and run the test under that user.  Without them
# those cases skip; the policy-only cases (S6, P5, E6) run as any user.
#

anoint_bin()
{
	if [ -n "${ANOINT}" ] && [ -x "${ANOINT}" ]; then
		printf '%s\n' "${ANOINT}"
		return 0
	fi
	for p in /usr/bin/anoint "$(dirname "$0")/anoint"; do
		if [ -x "$p" ]; then
			printf '%s\n' "$p"
			return 0
		fi
	done
	return 1
}

# Skip unless this session carries an ambient lookup channel and anoint is
# installed; print the anoint path.
# Must run in the test's own shell (never inside $(...)): atf_skip from a
# subshell does not skip the case, it just yields an empty string.
require_plane()
{
	anoint_bin >/dev/null || atf_skip "anoint(1) not installed"
	[ -n "${SERVICE_LOOKUP_FD}" ] ||
	    atf_skip "no ambient lookup channel here (not a plane session)"
}

require_password()
{
	[ -n "${AUTHAGENT_TEST_PASSWORD}" ] ||
	    atf_skip "set AUTHAGENT_TEST_USER/AUTHAGENT_TEST_PASSWORD and run" \
	    "as that user to exercise the password path"
	[ "$(id -un)" = "${AUTHAGENT_TEST_USER}" ] ||
	    atf_skip "run as AUTHAGENT_TEST_USER (${AUTHAGENT_TEST_USER})"
}

name_to_elevate()
{
	printf '%s\n' "${AUTHAGENT_TEST_NAME:-system.notify.system}"
}

# Feed the password to anoint(1) on a pseudo-terminal via script(1) so
# readpassphrase(3) reads it.  $1 = password, rest = anoint arguments.
anoint_with_password()
{
	local password="$1" out driver
	shift
	# anoint reads the password from /dev/tty (readpassphrase, RPP_REQUIRE_TTY,
	# the tty-only rule sudo and doas use); readpassphrase flushes input typed
	# before the prompt (tcsetattr TCSAFLUSH), so a plain `printf pw | script`
	# races and loses.  pty_askpass drives a real pty and sends the password
	# only after the prompt appears -- deterministic.
	driver="$(atf_get_srcdir)/pty_askpass"
	[ -x "${driver}" ] || atf_skip "pty_askpass helper not built"
	out=$(mktemp -t anoint)
	"${driver}" "${password}" "$@" > "${out}" 2>&1
	rc=$?
	cat "${out}"
	rm -f "${out}"
	return ${rc}
}
# ---- S6 / P5: refusal before any prompt -------------------------------------

atf_test_case s6_default_user_eperm_no_prompt
s6_default_user_eperm_no_prompt_head()
{
	atf_set "descr" "S6/P5: a principal that may not elevate NAME gets" \
	    "'not permitted' with no password prompt (stdin closed)"
}
s6_default_user_eperm_no_prompt_body()
{
	local bin

	require_plane
	bin=$(anoint_bin)
	# A name no shipped policy lists in may_elevate.  With stdin closed a
	# prompt would fail differently ("no password"); -n avoids the tty too.
	atf_check -s exit:1 -o empty -e match:"not permitted" \
	    "${bin}" -n org.5bsd.test.never.granted /usr/bin/true
	# The policy answer is the same whether or not a password is sent.
	atf_check -s exit:1 -e match:"not permitted" \
	    "${bin}" -n org.5bsd.test.never.granted /usr/bin/true </dev/null
}

atf_test_case invalid_name_rejected
invalid_name_rejected_head()
{
	atf_set "descr" "anoint rejects '*' and non-dotted names client-side"
}
invalid_name_rejected_body()
{
	local bin

	require_plane
	bin=$(anoint_bin)
	atf_check -s exit:1 -e match:"anoint:" "${bin}" -n '*' /usr/bin/true
	atf_check -s exit:1 -e match:"anoint:" "${bin}" -n nodot /usr/bin/true
	atf_check -s exit:1 -e match:"anoint:" "${bin}" -n '' /usr/bin/true
}

# ---- E6: agent down fails soft ----------------------------------------------

atf_test_case e6_no_session_channel_fails_soft
e6_no_session_channel_fails_soft_head()
{
	atf_set "descr" "E6: without a session channel anoint fails at once" \
	    "with a clear error, no hang"
}
e6_no_session_channel_fails_soft_body()
{
	local bin

	require_plane
	bin=$(anoint_bin) || atf_skip "anoint(1) not installed"
	# Strip the ambient channel from the environment: the client must
	# refuse immediately rather than wait on a lookup that cannot happen.
	atf_check -s exit:1 -e match:"no session channel" \
	    env -u SERVICE_LOOKUP_FD "${bin}" -n system.notify.system \
	    /usr/bin/true 3<&-
}

# ---- P3 / E1 / E3: the success path -----------------------------------------

atf_test_case p3_e1_success_session_plus_one
p3_e1_success_session_plus_one_head()
{
	atf_set "descr" "P3/E1: correct password -> CMD runs with the" \
	    "elevated channel installed, uid unchanged; the shell after is" \
	    "unchanged (P2)"
}
p3_e1_success_session_plus_one_body()
{
	local bin name out uid_in uid_out fd_in fd_out

	require_plane
	bin=$(anoint_bin)
	require_password
	name=$(name_to_elevate)
	uid_in=$(id -u)
	fd_in="${SERVICE_LOOKUP_FD}"
	out=$(anoint_with_password "${AUTHAGENT_TEST_PASSWORD}" \
	    "${bin}" "${name}" /bin/sh -c 'echo "uid=$(id -u) fd=$SERVICE_LOOKUP_FD"') ||
	    atf_fail "anoint ${name} failed: ${out}"
	uid_out=$(printf '%s\n' "${out}" | sed -n 's/.*uid=\([0-9]*\).*/\1/p' | tail -1)
	fd_out=$(printf '%s\n' "${out}" | sed -n 's/.*fd=\([0-9]*\).*/\1/p' | tail -1)
	atf_check_equal "${uid_in}" "${uid_out}"
	# E1: the command ran on a NEW ambient channel (session set + NAME).
	[ -n "${fd_out}" ] || atf_fail "CMD saw no SERVICE_LOOKUP_FD: ${out}"
	[ "${fd_out}" != "${fd_in}" ] ||
	    atf_fail "CMD inherited the unelevated channel (fd ${fd_in})"
	# P2 after P3: the calling shell still has only its session set.
	atf_check_equal "${fd_in}" "${SERVICE_LOOKUP_FD}"
}

atf_test_case e3_second_anoint_prompts_again
e3_second_anoint_prompts_again_head()
{
	atf_set "descr" "E3: nothing is cached -- a second anoint with a wrong" \
	    "password fails even right after a success"
}
e3_second_anoint_prompts_again_body()
{
	local bin name

	require_plane
	bin=$(anoint_bin)
	require_password
	name=$(name_to_elevate)
	anoint_with_password "${AUTHAGENT_TEST_PASSWORD}" \
	    "${bin}" "${name}" /usr/bin/true >/dev/null ||
	    atf_fail "first anoint failed"
	if anoint_with_password "definitely-not-${AUTHAGENT_TEST_PASSWORD}" \
	    "${bin}" "${name}" /usr/bin/true >/dev/null; then
		atf_fail "second anoint succeeded with a wrong password"
	fi
}

# ---- P4: wrong password fails closed ----------------------------------------

atf_test_case p4_wrong_password_fails_closed
p4_wrong_password_fails_closed_head()
{
	atf_set "descr" "P4: a wrong password yields no channel and exit 1"
}
p4_wrong_password_fails_closed_body()
{
	local bin name out

	require_plane
	bin=$(anoint_bin)
	require_password
	name=$(name_to_elevate)
	if out=$(anoint_with_password "wrong-${AUTHAGENT_TEST_PASSWORD}" \
	    "${bin}" "${name}" /bin/sh -c 'echo RAN'); then
		atf_fail "wrong password accepted: ${out}"
	fi
	case "${out}" in
	*RAN*)	atf_fail "CMD ran despite a wrong password" ;;
	esac
	case "${out}" in
	*"authentication failed"*)	;;
	*)	atf_fail "expected 'authentication failed', got: ${out}" ;;
	esac
}

# ---- P9: strict-admin profile -----------------------------------------------

atf_test_case p9_strict_admin_profile
p9_strict_admin_profile_head()
{
	atf_set "descr" "P9: under admin { anointments = []; may_elevate = ['*'] }" \
	    "a wheel user reaches a gated endpoint only through anoint"
	atf_set "require.user" "root"
}
p9_strict_admin_profile_body()
{
	local bin

	require_plane
	bin=$(anoint_bin)
	# The profile is a policy edit the operator makes; this test only runs
	# when the running policy IS that profile (it cannot rewrite the live
	# policy of the plane it is running on).
	grep -Eq 'may_elevate *= *\[ *"\*" *\]' \
	    /Capabilities/Config/principal-policy.ucl 2>/dev/null ||
	    atf_skip "principal-policy.ucl is not the strict-admin profile"
	[ -n "${AUTHAGENT_TEST_PASSWORD}" ] ||
	    atf_skip "set AUTHAGENT_TEST_PASSWORD (root's) to drive P9"
	# Without anointing, the gated name is unreachable from this shell.
	atf_check -s not-exit:0 notifyctl publish system.test.p9 "p9" 2>/dev/null
	# With it, the same command works for that one invocation.
	anoint_with_password "${AUTHAGENT_TEST_PASSWORD}" "${bin}" \
	    system.notify.system notifyctl publish system.test.p9 "p9" ||
	    atf_fail "anoint system.notify.system notifyctl failed"
}

atf_init_test_cases()
{
	atf_add_test_case s6_default_user_eperm_no_prompt
	atf_add_test_case invalid_name_rejected
	atf_add_test_case e6_no_session_channel_fails_soft
	atf_add_test_case p3_e1_success_session_plus_one
	atf_add_test_case e3_second_anoint_prompts_again
	atf_add_test_case p4_wrong_password_fails_closed
	atf_add_test_case p9_strict_admin_profile
}
