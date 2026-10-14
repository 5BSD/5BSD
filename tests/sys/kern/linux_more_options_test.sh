# SPDX-License-Identifier: BSD-2-Clause
atf_test_case more_options
more_options_head()
{
	atf_set "descr" "Linux created query, write hints, task pidfd passing"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld brandelf"
	atf_set "require.kmods" "linux64"
}
more_options_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o linux_more_options \
	    "$(atf_get_srcdir)/linux_more_options.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux linux_more_options
	for name in file_options passpidfd; do
		atf_check -s exit:0 -o empty -e empty ./linux_more_options "$name"
	done
}
atf_init_test_cases()
{
	atf_add_test_case more_options
}
