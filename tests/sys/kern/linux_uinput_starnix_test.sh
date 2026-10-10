# SPDX-License-Identifier: BSD-2-Clause
uinput_head()
{
	atf_set "descr" "Linux uinput setup translation and device lifecycle"
	atf_set "require.arch" "amd64"
	atf_set "require.user" "root"
	atf_set "require.progs" "clang ld.lld brandelf"
	atf_set "require.kmods" "linux64 uinput"
	atf_set "timeout" "30"
}
uinput_run()
{
	[ -c /dev/uinput ] || atf_skip "uinput device unavailable"
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o probe \
	    "$(atf_get_srcdir)/linux_uinput_starnix.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux probe
	atf_check -s exit:0 -o empty -e empty ./probe "$1"
}
atf_test_case validation
validation_head() { uinput_head; }
validation_body() { uinput_run validation; }
atf_test_case lifecycle
lifecycle_head() { uinput_head; }
lifecycle_body() { uinput_run lifecycle; }
atf_test_case abs_setup
abs_setup_head() { uinput_head; }
abs_setup_body() { uinput_run abs_setup; }
atf_test_case event_key
event_key_head() { uinput_head; }
event_key_body() { uinput_run ekey; }
atf_test_case event_abs
event_abs_head() { uinput_head; }
event_abs_body() { uinput_run eabs; }
atf_test_case write_fault
write_fault_head() { uinput_head; }
write_fault_body() { uinput_run fault; }
atf_init_test_cases()
{
	atf_add_test_case validation
	atf_add_test_case lifecycle
	atf_add_test_case abs_setup
	atf_add_test_case event_key
	atf_add_test_case event_abs
	atf_add_test_case write_fault
}
