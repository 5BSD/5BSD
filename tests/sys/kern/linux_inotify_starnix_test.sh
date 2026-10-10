# SPDX-License-Identifier: BSD-2-Clause
metadata()
{
	atf_set "descr" "Linux inotify deletion ordering and hard-link watch lifetime"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld brandelf"
	atf_set "require.kmods" "linux64"
	atf_set "timeout" "60"
}
run_probe()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o inotify_starnix \
	    "$(atf_get_srcdir)/linux_inotify_starnix.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux inotify_starnix
	atf_check -s exit:0 -o empty -e empty ./inotify_starnix "$1"
}

atf_test_case ignored_without_delete_self
ignored_without_delete_self_head() { metadata; }
ignored_without_delete_self_body() { run_probe ignored_without_delete_self; }
atf_test_case delete_self_then_ignored
delete_self_then_ignored_head() { metadata; }
delete_self_then_ignored_body() { run_probe delete_self_then_ignored; }
atf_test_case child_before_parent
child_before_parent_head() { metadata; }
child_before_parent_body() { run_probe child_before_parent; }
atf_test_case open_directory_defers_self
open_directory_defers_self_head() { metadata; }
open_directory_defers_self_body() { run_probe open_directory_defers_self; }
atf_test_case watched_link_first
watched_link_first_head() { metadata; }
watched_link_first_body() { run_probe watched_link_first; }
atf_test_case watched_link_last
watched_link_last_head() { metadata; }
watched_link_last_body() { run_probe watched_link_last; }

atf_test_case open_directory_parent_first
open_directory_parent_first_head() { metadata; }
open_directory_parent_first_body() { run_probe open_directory_parent_first; }

atf_test_case cwd_defers_self
cwd_defers_self_head() { metadata; }
cwd_defers_self_body() { run_probe cwd_defers_self; }

atf_init_test_cases()
{
	atf_add_test_case ignored_without_delete_self
	atf_add_test_case delete_self_then_ignored
	atf_add_test_case child_before_parent
	atf_add_test_case open_directory_defers_self
	atf_add_test_case open_directory_parent_first
	atf_add_test_case cwd_defers_self
	atf_add_test_case watched_link_first
	atf_add_test_case watched_link_last
}
