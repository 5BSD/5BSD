# SPDX-License-Identifier: BSD-2-Clause
atf_test_case openflags
openflags_head()
{
	atf_set "descr" "Linux open/openat O_* flags incl. O_DSYNC vs O_SYNC and F_SETFL rules"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld"
	atf_set "require.kmods" "linux64"
	atf_set "require.user" "root"
	atf_set "timeout" "60"
}
openflags_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o openflags \
	    "$(atf_get_srcdir)/linux_openflags.c"
	./openflags 2>stderr.txt; rc=$?
	cat stderr.txt >&2
	[ $rc -eq 0 ] || atf_fail "exit status $rc"
}
atf_init_test_cases()
{
	atf_add_test_case openflags
}
