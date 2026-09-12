# SPDX-License-Identifier: BSD-2-Clause
atf_test_case pkey
pkey_head()
{
	atf_set "descr" "Linux pkey_alloc/pkey_free/pkey_mprotect semantics"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld"
	atf_set "require.kmods" "linux64"
}
pkey_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o pkey \
	    "$(atf_get_srcdir)/linux_pkey.c"
	# stderr carries "pku not available" on hosts without PKU/OSPKE (the
	# ENOSPC/EINVAL checks still ran); the exit status is the verdict.
	./pkey 2>stderr.txt; rc=$?
	cat stderr.txt >&2
	[ $rc -eq 0 ] || atf_fail "exit status $rc"
}
atf_init_test_cases()
{
	atf_add_test_case pkey
}
