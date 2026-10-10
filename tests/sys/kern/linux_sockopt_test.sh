# SPDX-License-Identifier: BSD-2-Clause
atf_test_case sockopt
sockopt_head()
{
	atf_set "descr" "Linux socket options, getsockopt truncation bounds and IP ancillary data translation"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang brandelf"
	atf_set "require.kmods" "linux64"
}
sockopt_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o sockopt \
	    "$(atf_get_srcdir)/linux_sockopt.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux sockopt
	atf_check -s exit:0 -o empty -e empty ./sockopt
}
atf_test_case translated_truncation
translated_truncation_head()
{
	atf_set "descr" "Linux translated socket options honor getsockopt buffer capacity"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld brandelf"
	atf_set "require.kmods" "linux64"
	atf_set "timeout" "30"
}
translated_truncation_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -DSOCKOPT_TRANSLATED_ONLY=1 \
	    -o translated_truncation "$(atf_get_srcdir)/linux_sockopt.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux translated_truncation
	atf_check -s exit:0 -o empty -e empty ./translated_truncation
}
atf_init_test_cases()
{
	atf_add_test_case sockopt
	atf_add_test_case translated_truncation
}
