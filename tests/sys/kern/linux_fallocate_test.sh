# SPDX-License-Identifier: BSD-2-Clause
atf_test_case fallocate
fallocate_head()
{
	atf_set "descr" "Linux fallocate modes: preallocation, PUNCH_HOLE|KEEP_SIZE, unsupported modes, validation"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld"
	atf_set "require.kmods" "linux64"
	atf_set "require.user" "root"
	atf_set "timeout" "120"
}
fallocate_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o fallocate \
	    "$(atf_get_srcdir)/linux_fallocate.c"
	./fallocate 2>stderr.txt; rc=$?
	cat stderr.txt >&2
	[ $rc -eq 0 ] || atf_fail "exit status $rc"
}
atf_init_test_cases()
{
	atf_add_test_case fallocate
}
