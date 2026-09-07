#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause

atf_test_case arguments
arguments_body()
{
	tool="$(atf_get_srcdir)/tzfsctl_success_bin"
	atf_check -s exit:1 -e match:'usage: tzfsctl' "$tool"
	atf_check -s exit:1 -e match:'unknown command' "$tool" unknown
	atf_check -s exit:1 -e match:'too many arguments' "$tool" ping extra
	atf_check -s exit:1 -e match:'expected one name' "$tool" release
	atf_check -s exit:1 -e match:'expected one name' "$tool" release a b
	atf_check -s exit:1 -e match:'missing name' "$tool" request
	atf_check -s exit:1 -e match:'too many names' "$tool" request a b
	atf_check -s exit:1 -e match:'unknown right' \
	    "$tool" request -r imaginary claim
}

atf_test_case commands
commands_body()
{
	tool="$(atf_get_srcdir)/tzfsctl_success_bin"
	atf_check -s exit:0 -o inline:'ok\n' -e empty "$tool" ping
	atf_check -s exit:0 -o match:'granted pool/components/claim' -e empty \
	    env TZFS_EXPECT_RIGHTS=1025 TZFS_EXPECT_LIFETIME=3 \
	    "$tool" request claim
	atf_check -s exit:0 -o match:'lifetime=0' -e empty \
	    env TZFS_EXPECT_RIGHTS=6 TZFS_EXPECT_LIFETIME=0 \
	    "$tool" request -l persistent -r props_write,snapshot claim
	atf_check -s exit:0 -o match:'lifetime=1' -e empty \
	    env TZFS_EXPECT_RIGHTS=262143 TZFS_EXPECT_LIFETIME=1 \
	    "$tool" request -l cache -r all claim
	atf_check -s exit:0 -o match:'lifetime=2' -e empty \
	    env TZFS_EXPECT_RIGHTS=1025 TZFS_EXPECT_LIFETIME=2 \
	    "$tool" request -l boot -r props_read -m claim
	atf_check -s exit:0 -o match:'mounted \(dirfd [0-9]+\)' -e empty \
	    env TZFS_EXPECT_RIGHTS=1025 TZFS_EXPECT_LIFETIME=3 \
	    "$tool" request -l lease -r props_read -m claim
	atf_check -s exit:0 -o inline:'released claim\n' -e empty \
	    "$tool" release claim
}

atf_test_case truncation_rejected
truncation_rejected_body()
{
	tool="$(atf_get_srcdir)/tzfsctl_success_bin"
	dataset=$(jot -b x 64 | tr -d '\n')
	rights=$(jot -b x 256 | tr -d '\n')
	atf_check -s exit:1 -e match:'dataset name is too long' \
	    "$tool" request "$dataset"
	atf_check -s exit:1 -e match:'rights list is too long' \
	    "$tool" request -r "$rights" claim
}

atf_test_case failures
failures_body()
{
	tool="$(atf_get_srcdir)/tzfsctl_success_bin"
	atf_check -s exit:1 -e match:'connect system.Filesystem' \
	    env TZFS_TEST_FAIL=connect "$tool" ping
	atf_check -s exit:1 -o inline:'no response\n' -e match:'client-closed' \
	    env TZFS_TEST_FAIL=ping TZFS_TEST_TRACE_CLOSE=1 "$tool" ping
	atf_check -s exit:1 -e match:'request claim: Input/output error' \
	    env TZFS_TEST_FAIL=request "$tool" request claim
	atf_check -s exit:1 -o match:'granted pool/components/claim' -e match:'mount: Input/output error' \
	    env TZFS_TEST_FAIL=mount "$tool" request -m claim
	atf_check -s exit:1 -e match:'release claim: Input/output error' \
	    env TZFS_TEST_FAIL=release "$tool" release claim
}

atf_init_test_cases()
{
	atf_add_test_case arguments
	atf_add_test_case commands
	atf_add_test_case truncation_rejected
	atf_add_test_case failures
}
