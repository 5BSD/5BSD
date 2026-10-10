# SPDX-License-Identifier: BSD-2-Clause
# Supported native subset; Linux-only per-thread/lock-table cases remain probes.
metadata()
{
    atf_set "descr" "Linux unshare descriptor/path isolation and native rejection boundaries"
    atf_set "require.arch" "amd64"
    atf_set "require.progs" "clang ld.lld brandelf"
    atf_set "require.kmods" "linux64"
    atf_set "require.user" "root"
    atf_set "timeout" "60"
}
run_probe()
{
    atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
        -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
        -O2 -Wall -Wextra -Werror -DUNSHARE_BSD_SUBSET -o unshare_probe \
        "$(atf_get_srcdir)/linux_unshare.c"
    atf_check -s exit:0 -o empty -e empty brandelf -t Linux unshare_probe
    atf_check -s exit:0 -o empty -e empty "$(pwd)/unshare_probe" "$1"
}

atf_test_case zero_preserves_sharing
zero_preserves_sharing_head() { metadata; }
zero_preserves_sharing_body() { run_probe zero_preserves_sharing; }

atf_test_case fs_detaches_only_paths_and_umask
fs_detaches_only_paths_and_umask_head() { metadata; }
fs_detaches_only_paths_and_umask_body() { run_probe fs_detaches_only_paths_and_umask; }

atf_test_case files_detaches_only_descriptors
files_detaches_only_descriptors_head() { metadata; }
files_detaches_only_descriptors_body() { run_probe files_detaches_only_descriptors; }

atf_test_case fs_files_detach_both
fs_files_detach_both_head() { metadata; }
fs_files_detach_both_body() { run_probe fs_files_detach_both; }

atf_test_case files_preserves_open_description
files_preserves_open_description_head() { metadata; }
files_preserves_open_description_body() { run_probe files_preserves_open_description; }

atf_test_case invalid_flags
invalid_flags_head() { metadata; }
invalid_flags_body() { run_probe invalid_flags; }

atf_test_case rejection_preserves_sharing
rejection_preserves_sharing_head() { metadata; }
rejection_preserves_sharing_body() { run_probe rejection_preserves_sharing; }

atf_test_case fs_unprivileged
fs_unprivileged_head() { metadata; }
fs_unprivileged_body() { run_probe fs_unprivileged; }

atf_test_case fs_repeated
fs_repeated_head() { metadata; }
fs_repeated_body() { run_probe fs_repeated; }

atf_test_case fs_fork_exec_lifetime
fs_fork_exec_lifetime_head() { metadata; }
fs_fork_exec_lifetime_body() { run_probe fs_fork_exec_lifetime; }

atf_test_case files_exec_detaches
files_exec_detaches_head() { metadata; }
files_exec_detaches_body() { run_probe files_exec_detaches; }

atf_test_case fs_exec_preserves_sharing
fs_exec_preserves_sharing_head() { metadata; }
fs_exec_preserves_sharing_body() { run_probe fs_exec_preserves_sharing; }

atf_test_case fs_root_lifetime
fs_root_lifetime_head() { metadata; }
fs_root_lifetime_body() { run_probe fs_root_lifetime; }

atf_test_case fs_concurrent_shared_mutation
fs_concurrent_shared_mutation_head() { metadata; }
fs_concurrent_shared_mutation_body() { run_probe fs_concurrent_shared_mutation; }

atf_test_case bsd_rejected_flags
bsd_rejected_flags_head() { metadata; }
bsd_rejected_flags_body() { run_probe bsd_rejected_flags; }

atf_test_case bsd_thread_rejection
bsd_thread_rejection_head() { metadata; }
bsd_thread_rejection_body() { run_probe bsd_thread_rejection; }

atf_test_case bsd_epoll_rejection
bsd_epoll_rejection_head() { metadata; }
bsd_epoll_rejection_body() { run_probe bsd_epoll_rejection; }

atf_test_case capmode
capmode_head() { metadata; }
capmode_body()
{
    atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
        -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
        -O2 -Wall -Wextra -Werror -DLINUX_PROBE -o capmode_probe \
        "$(atf_get_srcdir)/linux_unshare_capmode.c"
    atf_check -s exit:0 -o empty -e empty brandelf -t Linux capmode_probe
    atf_check -s exit:0 -o empty -e empty clang -O2 -Wall -Wextra -Werror \
        -o capmode_parent "$(atf_get_srcdir)/linux_unshare_capmode.c"
    atf_check -s exit:0 -o inline:"UNSHARE_CAPMODE result=-1 rc=0\n" \
        -e empty ./capmode_parent "$(pwd)/capmode_probe"
}
atf_init_test_cases()
{
    atf_add_test_case zero_preserves_sharing
    atf_add_test_case fs_detaches_only_paths_and_umask
    atf_add_test_case files_detaches_only_descriptors
    atf_add_test_case fs_files_detach_both
    atf_add_test_case files_preserves_open_description
    atf_add_test_case invalid_flags
    atf_add_test_case rejection_preserves_sharing
    atf_add_test_case fs_unprivileged
    atf_add_test_case fs_repeated
    atf_add_test_case fs_fork_exec_lifetime
    atf_add_test_case files_exec_detaches
    atf_add_test_case fs_exec_preserves_sharing
    atf_add_test_case fs_root_lifetime
    atf_add_test_case fs_concurrent_shared_mutation
    atf_add_test_case bsd_rejected_flags
    atf_add_test_case bsd_thread_rejection
    atf_add_test_case bsd_epoll_rejection
    atf_add_test_case capmode
}
