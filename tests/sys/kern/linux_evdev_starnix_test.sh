# SPDX-License-Identifier: BSD-2-Clause
# Synthetic input devices: run in disposable guests only.
evdev_head()
{
	atf_set "descr" "Linux evdev name query length and copyout bounds (synthetic device)"
	atf_set "require.arch" "amd64"
	atf_set "require.user" "root"
	atf_set "require.progs" "cc clang ld.lld brandelf"
	atf_set "require.kmods" "linux64 uinput"
	atf_set "timeout" "30"
}
evdev_run()
{
	[ -c /dev/uinput ] || atf_skip "uinput device unavailable"
	atf_check -s exit:0 -o empty -e empty cc -Wall -Wextra -Werror \
	    -o fixture "$(atf_get_srcdir)/linux_evdev_fixture.c"
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o probe \
	    "$(atf_get_srcdir)/linux_evdev_starnix.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux probe
	atf_check -s exit:0 -o empty -e empty ./fixture ./probe "$1"
}
atf_test_case zero_length
zero_length_head() { evdev_head; }
zero_length_body() { evdev_run zero; }
atf_test_case copy_bounds
copy_bounds_head() { evdev_head; }
copy_bounds_body() { evdev_run bounds; }
atf_test_case bitmap_zero_length
bitmap_zero_length_head() { evdev_head; }
bitmap_zero_length_body() { evdev_run mzero; }
atf_test_case bitmap_bounds
bitmap_bounds_head() { evdev_head; }
bitmap_bounds_body() { evdev_run mbounds; }
atf_init_test_cases()
{
	atf_add_test_case zero_length
	atf_add_test_case copy_bounds
	atf_add_test_case bitmap_zero_length
	atf_add_test_case bitmap_bounds
}
