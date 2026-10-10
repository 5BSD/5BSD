# SPDX-License-Identifier: BSD-2-Clause
# Native checks for regressions in the backend shared with Linux inotify.
metadata()
{
    atf_set "descr" "Native inotify reference, mapping and watch-removal lifetime"
    atf_set "require.progs" "${2:-cc}"
    atf_set "require.user" "${1:-unprivileged}"
    atf_set "timeout" "90"
}
run_probe()
{
    atf_check -s exit:0 -o empty -e empty cc -O2 -Wall -Wextra -Werror \
        -o lifetime_probe "$(atf_get_srcdir)/linux_inotify_lifetime.c"
    atf_check -s exit:0 -o inline:"LIFETIME_CASE $1 PASS\n" -e empty \
        ./lifetime_probe "$1"
}

atf_test_case dup
dup_head() { metadata; }
dup_body() { run_probe dup; }

atf_test_case opens
opens_head() { metadata; }
opens_body() { run_probe opens; }

atf_test_case directory
directory_head() { metadata; }
directory_body() { run_probe directory; }

atf_test_case shared_map
shared_map_head() { metadata; }
shared_map_body() { run_probe shared-map; }

atf_test_case private_map
private_map_head() { metadata; }
private_map_body() { run_probe private-map; }

atf_test_case late_watch cleanup
late_watch_head()
{
    metadata root "cc mount umount"
}
late_watch_body()
{
    atf_check -s exit:0 -o empty -e empty cc -O2 -Wall -Wextra -Werror \
        -o lifetime_probe "$(atf_get_srcdir)/linux_inotify_lifetime.c"
    mkdir fds scratch
    chmod 755 .
    chmod 1777 scratch
    atf_check -s exit:0 -o empty -e empty mount -t fdescfs -o nodup fdesc "$(pwd)/fds"
    atf_check -s exit:0 -o inline:"LIFETIME_CASE late-watch PASS\n" -e empty \
        env INOTIFY_FD_ROOT="$(pwd)/fds" TMPDIR="$(pwd)/scratch" \
        ./lifetime_probe late-watch unprivileged
}
late_watch_cleanup()
{
    if [ -d fds ]; then umount "$(pwd)/fds" 2>/dev/null || true; fi
}

atf_test_case hardlink
hardlink_head() { metadata; }
hardlink_body() { run_probe hardlink; }

atf_test_case replace
replace_head() { metadata; }
replace_body() { run_probe replace; }

atf_test_case remove_watch
remove_watch_head() { metadata; }
remove_watch_body() { run_probe remove-watch; }

atf_test_case fork_exit
fork_exit_head() { metadata; }
fork_exit_body() { run_probe fork-exit; }

atf_test_case close_watches
close_watches_head() { metadata; }
close_watches_body() { run_probe close-watches; }

atf_init_test_cases()
{
    atf_add_test_case dup
    atf_add_test_case opens
    atf_add_test_case directory
    atf_add_test_case shared_map
    atf_add_test_case private_map
    atf_add_test_case late_watch
    atf_add_test_case hardlink
    atf_add_test_case replace
    atf_add_test_case remove_watch
    atf_add_test_case fork_exit
    atf_add_test_case close_watches
}
