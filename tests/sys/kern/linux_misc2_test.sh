# SPDX-License-Identifier: BSD-2-Clause
atf_test_case misc2
misc2_head()
{
	atf_set "descr" "Linux setfsuid/setfsgid, sched_setattr/getattr, process_madvise, waitid(P_PIDFD), prctl, syslog and mlock2"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang"
	atf_set "require.kmods" "linux64"
}
misc2_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o misc2 \
	    "$(atf_get_srcdir)/linux_misc2.c"
	# The binary skips (exit 0, one-line note on stderr) when it is not
	# started under SCHED_OTHER.
	atf_check -s exit:0 -o empty -e ignore ./misc2
}
atf_init_test_cases()
{
	atf_add_test_case misc2
}
