# SPDX-License-Identifier: BSD-2-Clause
atf_test_case aio

aio_head()
{
	atf_set "descr" "Linux legacy AIO context, submission, completion and rejection semantics"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld brandelf timeout"
	atf_set "require.kmods" "linux64"
}

aio_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o aio \
	    "$(atf_get_srcdir)/linux_aio.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux aio
	atf_check -s exit:0 -o empty -e empty timeout 30 ./aio
}

atf_init_test_cases()
{
	atf_add_test_case aio
}
