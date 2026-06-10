#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# ATF tests for libcapability — cap_daemon_label_allowed()
#

require_cc()
{
	if ! command -v cc >/dev/null 2>&1; then
		atf_skip "cc not available"
	fi
}

build_label_check()
{
	require_cc
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
	atf_check -s exit:0 -e ignore cc -Wall \
	    -I/usr/src/lib/libcapability \
	    -o label_check label_check.c -lcapability -lservice
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
}
