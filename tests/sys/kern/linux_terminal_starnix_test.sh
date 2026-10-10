# SPDX-License-Identifier: BSD-2-Clause
terminal_head()
{
	atf_set "descr" "Linux terminal input flushing and packet mode"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld brandelf"
	atf_set "require.kmods" "linux64"
	atf_set "timeout" "30"
}
terminal_run()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o probe \
	    "$(atf_get_srcdir)/linux_terminal_starnix.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux probe
	atf_check -s exit:0 -o empty -e empty ./probe "$1"
}
atf_test_case flush_input
flush_input_head() { terminal_head; }
flush_input_body() { terminal_run flush_input; }
atf_test_case packet_mode
packet_mode_head() { terminal_head; }
packet_mode_body() { terminal_run packet_mode; }
atf_test_case packet_events
packet_events_head() { terminal_head; }
packet_events_body() { terminal_run packet_events; }
atf_test_case master_nonblock
master_nonblock_head() { terminal_head; }
master_nonblock_body() { terminal_run master_nonblock; }
atf_init_test_cases()
{
	atf_add_test_case flush_input
	atf_add_test_case packet_mode
	atf_add_test_case packet_events
	atf_add_test_case master_nonblock
}
