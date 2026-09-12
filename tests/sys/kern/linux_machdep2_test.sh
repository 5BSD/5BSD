# SPDX-License-Identifier: BSD-2-Clause
atf_test_case machdep2
machdep2_head()
{
	atf_set "descr" "Linux readahead, restart_syscall and arch_prctl feature queries"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld"
	atf_set "require.kmods" "linux64"
}
machdep2_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o machdep2 \
	    "$(atf_get_srcdir)/linux_machdep2.c"
	atf_check -s exit:0 -o ignore -e empty ./machdep2
}
atf_init_test_cases()
{
	atf_add_test_case machdep2
}
