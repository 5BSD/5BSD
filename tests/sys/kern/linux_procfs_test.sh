# SPDX-License-Identifier: BSD-2-Clause
atf_test_case procfs
procfs_head()
{
	atf_set "descr" "${1:-Linuxulator procfs/sysfs cgroup, cpuset, THP size and cmdline seeks}"
	atf_set "require.arch" "amd64"
	atf_set "require.progs" "clang ld.lld brandelf"
	atf_set "require.kmods" "linux64"
	atf_set "require.user" "root"
	atf_set "timeout" "60"
}
procfs_body()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o procfs "$(atf_get_srcdir)/linux_procfs.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux procfs
	./procfs 2>stderr.txt; rc=$?
	cat stderr.txt >&2
	[ $rc -eq 0 ] || atf_fail "exit status $rc"
}
starnix_run()
{
	atf_check -s exit:0 -o empty -e empty clang --target=x86_64-linux-gnu \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o probe \
	    "$(atf_get_srcdir)/linux_procfs_starnix.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux probe
	atf_check -s exit:0 -o empty -e empty ./probe "$1"
}
atf_test_case uptime_by_char
uptime_by_char_head() { procfs_head "Linux proc uptime partial reads retain a per-open snapshot"; }
uptime_by_char_body() { starnix_run uptime_by_char; }
atf_test_case uptime_dup
uptime_dup_head() { procfs_head "Linux proc uptime snapshot survives closing the original duplicate"; }
uptime_dup_body() { starnix_run uptime_dup; }
atf_test_case uptime_fork
uptime_fork_head() { procfs_head "Linux proc uptime snapshot survives fork and parent descriptor close"; }
uptime_fork_body() { starnix_run uptime_fork; }
atf_test_case uptime_seek
uptime_seek_head() { procfs_head; }
uptime_seek_body() { starnix_run uptime_seek; }
atf_test_case uptime_reopen
uptime_reopen_head() { procfs_head; }
uptime_reopen_body() { starnix_run uptime_reopen; }
atf_test_case boot_id
boot_id_head() { procfs_head; }
boot_id_body() { starnix_run boot_id; }
atf_test_case snapshot_teardown cleanup
snapshot_teardown_head()
{
	atf_set "descr" "Native procfs snapshot descriptors survive forced unmount until close"
	atf_set "require.progs" "cc umount"
	atf_set "require.kmods" "linprocfs"
	atf_set "require.user" "root"
	atf_set "timeout" "120"
}
snapshot_teardown_body()
{
	atf_check -s exit:0 -o empty -e empty cc -O2 -Wall -Wextra -Werror \
	    -o teardown "$(atf_get_srcdir)/procfs_snapshot_teardown.c"
	mkdir procfs-mount
	atf_check -s exit:0 \
	    -o inline:"PROCFS_SNAPSHOT_TEARDOWN PASS 16 mounts 512 descriptors\n" \
	    -e empty ./teardown procfs-mount
}
snapshot_teardown_cleanup()
{
	if [ -d procfs-mount ]; then
		umount -f "$(pwd)/procfs-mount" 2>/dev/null || true
	fi
}
atf_init_test_cases()
{
	atf_add_test_case snapshot_teardown
	atf_add_test_case procfs
	atf_add_test_case uptime_dup
	atf_add_test_case uptime_fork
	atf_add_test_case uptime_by_char
	atf_add_test_case uptime_seek
	atf_add_test_case uptime_reopen
	atf_add_test_case boot_id
}
