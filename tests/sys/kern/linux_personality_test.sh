# SPDX-License-Identifier: BSD-2-Clause
atf_test_case personality
personality_head()
{
	atf_set "descr" "Linux personality query/set/persistence, ADDR_NO_RANDOMIZE and secure-exec (AT_SECURE, PER_CLEAR_ON_SETID)"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld"
	atf_set "require.kmods" "linux64"
	atf_set "require.user" "root"
	atf_set "timeout" "120"
}
personality_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o personality \
	    "$(atf_get_srcdir)/linux_personality.c"
	# A setgid copy exercises the set-id image secure-exec rules.
	atf_check cp personality personality_sgid
	atf_check chown root:operator personality_sgid
	atf_check chmod 2755 personality_sgid
	./personality ./personality_sgid 2>stderr.txt; rc=$?
	cat stderr.txt >&2
	[ $rc -eq 0 ] || atf_fail "exit status $rc"
}
atf_init_test_cases()
{
	atf_add_test_case personality
}
