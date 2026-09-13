# SPDX-License-Identifier: BSD-2-Clause
atf_test_case statmount
statmount_head()
{
	atf_set "descr" "Linux listmount/statmount: enumerate mounts, query fs_type/mnt_point/root, validation"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld"
	atf_set "require.kmods" "linux64"
	atf_set "require.user" "root"
	atf_set "timeout" "60"
}
statmount_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o statmount \
	    "$(atf_get_srcdir)/linux_statmount.c"
	./statmount 2>stderr.txt; rc=$?
	cat stderr.txt >&2
	[ $rc -eq 0 ] || atf_fail "exit status $rc"
}
atf_init_test_cases()
{
	atf_add_test_case statmount
}
