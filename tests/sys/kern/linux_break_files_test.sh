# SPDX-License-Identifier: BSD-2-Clause
atf_test_case break_files
break_files_head()
{
	atf_set "descr" "Linux adversarial files: RESOLVE_BENEATH fuzz, O_PATH, close_range, rename races, seals, getdents, xattr, EFAULT"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld"
	atf_set "require.kmods" "linux64"
	atf_set "require.user" "root"
	atf_set "timeout" "300"
}
break_files_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o break_files \
	    "$(atf_get_srcdir)/linux_break_files.c"
	./break_files 2>stderr.txt; rc=$?
	cat stderr.txt >&2
	[ $rc -eq 0 ] || atf_fail "exit status $rc"
}
atf_init_test_cases()
{
	atf_add_test_case break_files
}
