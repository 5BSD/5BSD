#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# ATF tests for libcapability — cap_daemon_label_allowed()
#

test_cppflags=
if [ -r /usr/src/lib/libcapability/capability.h ]; then
	test_cppflags="-I/usr/src/lib/libcapability -I/usr/src/lib/libservice -I/usr/src/sys"
fi

find_libcapability()
{
	local p _m _p

	_m=$(uname -m)
	_p=$(uname -p)
	for p in \
	    /usr/obj/usr/src/${_m}.${_p}/lib/libcapability/libcapability.a \
	    /usr/lib/libcapability.a
	do
		if [ -r "$p" ]; then
			capability_archive=$p
			return
		fi
	done
	atf_skip "libcapability static library not found"
}

find_libservice()
{
	local p _m _p

	_m=$(uname -m)
	_p=$(uname -p)
	for p in \
	    /usr/obj/usr/src/${_m}.${_p}/lib/libservice/libservice.a \
	    /usr/lib/libservice.a
	do
		if [ -r "$p" ]; then
			service_archive=$p
			return
		fi
	done
	atf_skip "libservice static library not found"
}

require_cc()
{
	if ! command -v cc >/dev/null 2>&1; then
		atf_skip "cc not available"
	fi
}

build_label_check()
{
	require_cc
	find_libcapability
	find_libservice
	cat > label_check.c <<'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include "capability.h"

int
main(int argc, char **argv)
{
	if (argc != 3)
		return (2);
	if (cap_daemon_label_allowed(argv[1], argv[2]))
		printf("allowed\n");
	else
		printf("denied\n");
	return (cap_daemon_label_allowed(argv[1], argv[2]) ? 0 : 1);
}
CEOF
	atf_check -s exit:0 -e ignore cc -Wall $test_cppflags \
	    -o label_check label_check.c "$capability_archive" \
	    "$service_archive"
}

# -----------------------------------------------------------------------
# label_allowed_exact_match
# -----------------------------------------------------------------------
atf_test_case label_allowed_exact_match cleanup
label_allowed_exact_match_head()
{
	atf_set "descr" "Exact label match returns allowed"
}
label_allowed_exact_match_body()
{
	build_label_check
	printf "org.test.foo\n" > allow.conf
	atf_check -s exit:0 -o match:"allowed" \
	    ./label_check allow.conf "org.test.foo"
}
label_allowed_exact_match_cleanup()
{
	rm -f label_check label_check.c allow.conf
}

# -----------------------------------------------------------------------
# label_allowed_wildcard
# -----------------------------------------------------------------------
atf_test_case label_allowed_wildcard cleanup
label_allowed_wildcard_head()
{
	atf_set "descr" "Wildcard entry allows any label"
}
label_allowed_wildcard_body()
{
	build_label_check
	printf "*\n" > allow.conf
	atf_check -s exit:0 -o match:"allowed" \
	    ./label_check allow.conf "anything.at.all"
}
label_allowed_wildcard_cleanup()
{
	rm -f label_check label_check.c allow.conf
}

# -----------------------------------------------------------------------
# label_allowed_not_listed
# -----------------------------------------------------------------------
atf_test_case label_allowed_not_listed cleanup
label_allowed_not_listed_head()
{
	atf_set "descr" "Unlisted label is denied"
}
label_allowed_not_listed_body()
{
	build_label_check
	printf "org.test.foo\n" > allow.conf
	atf_check -s exit:1 -o match:"denied" \
	    ./label_check allow.conf "org.test.bar"
}
label_allowed_not_listed_cleanup()
{
	rm -f label_check label_check.c allow.conf
}

# -----------------------------------------------------------------------
# label_allowed_empty_file
# -----------------------------------------------------------------------
atf_test_case label_allowed_empty_file cleanup
label_allowed_empty_file_head()
{
	atf_set "descr" "Empty allow file denies all labels"
}
label_allowed_empty_file_body()
{
	build_label_check
	: > allow.conf
	atf_check -s exit:1 -o match:"denied" \
	    ./label_check allow.conf "org.test.foo"
}
label_allowed_empty_file_cleanup()
{
	rm -f label_check label_check.c allow.conf
}

# -----------------------------------------------------------------------
# label_allowed_missing_file
# -----------------------------------------------------------------------
atf_test_case label_allowed_missing_file cleanup
label_allowed_missing_file_head()
{
	atf_set "descr" "Missing allow file denies all labels"
}
label_allowed_missing_file_body()
{
	build_label_check
	atf_check -s exit:1 -o match:"denied" \
	    ./label_check /nonexistent/allow.conf "org.test.foo"
}
label_allowed_missing_file_cleanup()
{
	rm -f label_check label_check.c
}

# -----------------------------------------------------------------------
# label_allowed_comments
# -----------------------------------------------------------------------
atf_test_case label_allowed_comments cleanup
label_allowed_comments_head()
{
	atf_set "descr" "Comments and blank lines are ignored"
}
label_allowed_comments_body()
{
	build_label_check
	cat > allow.conf <<'EOF'
# This is a comment
org.test.real

# Another comment

org.test.also.real
EOF
	atf_check -s exit:0 -o match:"allowed" \
	    ./label_check allow.conf "org.test.real"
	atf_check -s exit:0 -o match:"allowed" \
	    ./label_check allow.conf "org.test.also.real"
	atf_check -s exit:1 -o match:"denied" \
	    ./label_check allow.conf "# This"
	atf_check -s exit:1 -o match:"denied" \
	    ./label_check allow.conf ""
}
label_allowed_comments_cleanup()
{
	rm -f label_check label_check.c allow.conf
}

# -----------------------------------------------------------------------
# daemon_lifecycle_authorization_order
# -----------------------------------------------------------------------
atf_test_case daemon_lifecycle_authorization_order cleanup
daemon_lifecycle_authorization_order_head()
{
	atf_set "descr" "Daemon activation is mandatory and precedes protection and registration"
}
daemon_lifecycle_authorization_order_body()
{
	find_libcapability
	require_cc
	cat > lifecycle_check.c <<'CEOF'
#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <libservice.h>
#include "capability.h"

static char calls[16];
static size_t ncalls;
static int authorize_error;
static int protect_error;

static void
record(char c)
{
	calls[ncalls++] = c;
	calls[ncalls] = '\0';
}

int service_init(void) { record('I'); return (0); }
int service_authorize_capabilities(void)
{
	record('A');
	if (authorize_error != 0) {
		errno = authorize_error;
		return (-1);
	}
	return (0);
}
int service_protect(uint32_t flags)
{
	uint32_t expected;

	record('P');
	expected = SERVICE_PROTECT_EXTERNAL;
	if (flags != expected) {
		errno = EINVAL;
		return (-1);
	}
	if (protect_error != 0) {
		errno = protect_error;
		return (-1);
	}
	return (0);
}
int service_register(const char *name)
{
	(void)name;
	record('R');
	errno = EIO;
	return (-1);
}
int service_ready(void) { record('Y'); return (-1); }
int service_channel_fd(void) { return (-1); }
int service_accept(char *label, size_t len)
{
	(void)label; (void)len; return (-1);
}
ssize_t service_recv(int fd, void *buf, size_t len, int *recvfd)
{
	(void)fd; (void)buf; (void)len; (void)recvfd; return (-1);
}
int service_send(int fd, const void *buf, size_t len)
{
	(void)fd; (void)buf; (void)len; return (-1);
}

static int handler(int fd, const char *label, void *arg)
{
	(void)fd; (void)label; (void)arg; return (0);
}

int
main(void)
{
	struct cap_daemon_config cfg = {
		.service_name = "org.test.lifecycle",
		.handler = handler,
	};

	authorize_error = EACCES;
	if (cap_daemon_run(&cfg) != -1 || errno != EACCES ||
	    strcmp(calls, "IA") != 0)
		return (1);
	ncalls = 0;
	calls[0] = '\0';
	authorize_error = 0;
	protect_error = EPERM;
	if (cap_daemon_run(&cfg) != -1 || errno != EPERM ||
	    strcmp(calls, "IAP") != 0)
		return (2);
	ncalls = 0;
	calls[0] = '\0';
	protect_error = 0;
	if (cap_daemon_run(&cfg) != -1 || errno != EIO ||
	    strcmp(calls, "IAPR") != 0)
		return (3);
	return (0);
}
CEOF
	atf_check -s exit:0 -e ignore cc -Wall -Wextra $test_cppflags \
	    -o lifecycle_check lifecycle_check.c "$capability_archive"
	atf_check -s exit:0 ./lifecycle_check
}
daemon_lifecycle_authorization_order_cleanup()
{
	rm -f lifecycle_check lifecycle_check.c
}

# -----------------------------------------------------------------------
# Init
# -----------------------------------------------------------------------
atf_init_test_cases()
{
	atf_add_test_case label_allowed_exact_match
	atf_add_test_case label_allowed_wildcard
	atf_add_test_case label_allowed_not_listed
	atf_add_test_case label_allowed_empty_file
	atf_add_test_case label_allowed_missing_file
	atf_add_test_case label_allowed_comments
	atf_add_test_case daemon_lifecycle_authorization_order
}
