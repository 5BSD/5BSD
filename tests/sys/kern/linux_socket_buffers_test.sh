# SPDX-License-Identifier: BSD-2-Clause
buffer_head()
{
	atf_set "descr" "Linux socket buffer sizing, limits and denied force options"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld brandelf"
	atf_set "require.kmods" "linux64"
	atf_set "require.user" "unprivileged"
	atf_set "timeout" "30"
}
buffer_run()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o probe \
	    "$(atf_get_srcdir)/linux_socket_buffers.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux probe
	atf_check -s exit:0 -o empty -e empty ./probe "$1"
}
atf_test_case doubled
doubled_head() { buffer_head; }
doubled_body() { buffer_run doubled; }
atf_test_case limits
limits_head() { buffer_head; }
limits_body() { buffer_run limits; }
atf_test_case rejected
rejected_head() { buffer_head; }
rejected_body() { buffer_run rejected; }
atf_init_test_cases()
{
	atf_add_test_case doubled
	atf_add_test_case limits
	atf_add_test_case rejected
}
