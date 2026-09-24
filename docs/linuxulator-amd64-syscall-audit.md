# amd64 Linux64 syscall dispatch audit — 2026-09-21

Scope: the current local x86_64 table through slot 472. No Linux32 or arm64.
This is a complete entry-point inventory, not a fresh semantic audit or runtime
qualification of every command, flag, ioctl, socket option and lifecycle.
Names come from the coverage inventory; handlers and missing status were
independently recounted from the generated dispatch table and active stub lists.
The generated table is checked against the master slot classifications.

## Percentages

| Classification | Count | Share of 386 named entries |
|---|---:|---:|
| Handler present (includes partial and validation-only behavior) | 333 | 86.3% |
| ENOSYS macro stubs | 36 | 9.3% |
| Reject-only seccomp | 1 | 0.3% |
| Historical unimplemented entries | 15 | 3.9% |

Percentages round independently. Excluding the 15 historical entries gives
333/371 = **89.8% handler coverage**, with 38/371 = **10.2% missing**.
Slots 337–423 are 87 unnamed holes and are excluded. Local slot 472 (`fchroot`)
is included; these figures are for this repository's table, not a claim of
coverage of every current upstream Linux syscall or ABI.

**No defensible percentage of fully Linux-compatible syscalls is established.**
Even the 333-handler category includes validation-only NUMA setters/migration:
`mbind`, `set_mempolicy`, `set_mempolicy_home_node`, and `migrate_pages` can
return success without enforcing the requested policy or moving pages.
Do not describe all 333 as fully functional. Partial annotations below are
known examples, not an exhaustive list of every handler's limitations.

See [option coverage](linuxulator-syscall-coverage.md),
[missing-call prerequisites](linuxulator-missing-syscalls-handoff.md), and
[recorded VM qualification](linuxulator-implementation-gate.md).

## Missing or partial active entries (38)

| Number | Syscall | Status |
|---:|---|---|
| 155 | `pivot_root` | Missing: ENOSYS stub |
| 175 | `init_module` | Missing: ENOSYS stub |
| 176 | `delete_module` | Missing: ENOSYS stub |
| 212 | `lookup_dcookie` | Missing: ENOSYS stub |
| 246 | `kexec_load` | Missing: ENOSYS stub |
| 248 | `add_key` | Missing: ENOSYS stub |
| 249 | `request_key` | Missing: ENOSYS stub |
| 250 | `keyctl` | Missing: ENOSYS stub |
| 298 | `perf_event_open` | Partial: current-thread software counters; PMU, sampling, groups and mmap ring pending |
| 300 | `fanotify_init` | Missing: ENOSYS stub |
| 301 | `fanotify_mark` | Missing: ENOSYS stub |
| 308 | `setns` | Missing: ENOSYS stub |
| 313 | `finit_module` | Missing: ENOSYS stub |
| 317 | `seccomp` | Missing: reject-only |
| 320 | `kexec_file_load` | Missing: ENOSYS stub |
| 321 | `bpf` | Missing: ENOSYS stub |
| 323 | `userfaultfd` | Missing: ENOSYS stub |
| 335 | `uretprobe` | Missing: ENOSYS stub |
| 336 | `uprobe` | Missing: ENOSYS stub |
| 428 | `open_tree` | Missing: ENOSYS stub |
| 429 | `move_mount` | Missing: ENOSYS stub |
| 430 | `fsopen` | Missing: ENOSYS stub |
| 431 | `fsconfig` | Missing: ENOSYS stub |
| 432 | `fsmount` | Missing: ENOSYS stub |
| 433 | `fspick` | Missing: ENOSYS stub |
| 442 | `mount_setattr` | Missing: ENOSYS stub |
| 444 | `landlock_create_ruleset` | Missing: ENOSYS stub |
| 445 | `landlock_add_rule` | Missing: ENOSYS stub |
| 446 | `landlock_restrict_self` | Missing: ENOSYS stub |
| 447 | `memfd_secret` | Missing: ENOSYS stub |
| 448 | `process_mrelease` | Missing: ENOSYS stub |
| 453 | `map_shadow_stack` | Missing: ENOSYS stub |
| 459 | `lsm_get_self_attr` | Missing: ENOSYS stub |
| 460 | `lsm_set_self_attr` | Missing: ENOSYS stub |
| 461 | `lsm_list_modules` | Missing: ENOSYS stub |
| 467 | `open_tree_attr` | Missing: ENOSYS stub |
| 470 | `listns` | Missing: ENOSYS stub |
| 471 | `rseq_slice_yield` | Missing: ENOSYS stub |

## Complete inventory (386 named entries)

“Handler present” means a dispatch implementation exists; it does not certify
complete semantics or test coverage. The handler column makes native aliases
and Linux-specific entry points explicit.

| Number | Linux syscall | Handler | Status / known limitation |
|---:|---|---|---|
| 0 | `read` | `sys_read` | Handler present |
| 1 | `Legacy Linux AIO (`io_setup`, `io_submit`, `io_getevents`, `io_cancel`, `io_destroy`, `io_pgetevents`)` | `linux_write` | Handler present |
| 2 | `Restartable sequences (`rseq`)` | `linux_open` | Handler present |
| 3 | `Seccomp filters` | `sys_close` | Handler present |
| 4 | `Quota interfaces` | `linux_newstat` | Handler present |
| 5 | `Namespace identity` | `linux_newfstat` | Handler present |
| 6 | `Process memory lifecycle` | `linux_newlstat` | Handler present |
| 7 | `Security metadata services` | `linux_poll` | Handler present |
| 8 | `Observability` | `linux_lseek` | Handler present |
| 9 | `mmap` | `linux_mmap2` | Handler present |
| 10 | `mprotect` | `linux_mprotect` | Handler present |
| 11 | `munmap` | `linux_munmap` | Handler present |
| 12 | `brk` | `linux_brk` | Handler present |
| 13 | `rt_sigaction` | `linux_rt_sigaction` | Handler present |
| 14 | `rt_sigprocmask` | `linux_rt_sigprocmask` | Handler present |
| 15 | `rt_sigreturn` | `linux_rt_sigreturn` | Handler present |
| 16 | `ioctl` | `linux_ioctl` | Handler present; Command/flag coverage varies; handler presence does not mean all operations work |
| 17 | `pread64` | `linux_pread` | Handler present |
| 18 | `pwrite64` | `linux_pwrite` | Handler present |
| 19 | `readv` | `sys_readv` | Handler present |
| 20 | `writev` | `linux_writev` | Handler present |
| 21 | `access` | `linux_access` | Handler present |
| 22 | `pipe` | `linux_pipe` | Handler present |
| 23 | `select` | `linux_select` | Handler present |
| 24 | `sched_yield` | `sys_sched_yield` | Handler present |
| 25 | `mremap` | `linux_mremap` | Handler present |
| 26 | `msync` | `linux_msync` | Handler present |
| 27 | `mincore` | `linux_mincore` | Handler present |
| 28 | `madvise` | `linux_madvise` | Handler present |
| 29 | `shmget` | `linux_shmget` | Handler present |
| 30 | `shmat` | `linux_shmat` | Handler present |
| 31 | `shmctl` | `linux_shmctl` | Handler present |
| 32 | `dup` | `sys_dup` | Handler present |
| 33 | `dup2` | `sys_dup2` | Handler present |
| 34 | `pause` | `linux_pause` | Handler present |
| 35 | `nanosleep` | `linux_nanosleep` | Handler present |
| 36 | `getitimer` | `linux_getitimer` | Handler present |
| 37 | `alarm` | `linux_alarm` | Handler present |
| 38 | `setitimer` | `linux_setitimer` | Handler present |
| 39 | `getpid` | `linux_getpid` | Handler present |
| 40 | `sendfile` | `linux_sendfile` | Handler present |
| 41 | `socket` | `linux_socket` | Handler present |
| 42 | `connect` | `linux_connect` | Handler present |
| 43 | `accept` | `linux_accept` | Handler present |
| 44 | `sendto` | `linux_sendto` | Handler present |
| 45 | `recvfrom` | `linux_recvfrom` | Handler present |
| 46 | `sendmsg` | `linux_sendmsg` | Handler present |
| 47 | `recvmsg` | `linux_recvmsg` | Handler present |
| 48 | `shutdown` | `linux_shutdown` | Handler present |
| 49 | `bind` | `linux_bind` | Handler present |
| 50 | `listen` | `linux_listen` | Handler present |
| 51 | `getsockname` | `linux_getsockname` | Handler present |
| 52 | `getpeername` | `linux_getpeername` | Handler present |
| 53 | `socketpair` | `linux_socketpair` | Handler present |
| 54 | `setsockopt` | `linux_setsockopt` | Handler present |
| 55 | `getsockopt` | `linux_getsockopt` | Handler present |
| 56 | `clone` | `linux_clone` | Handler present |
| 57 | `fork` | `linux_fork` | Handler present |
| 58 | `vfork` | `linux_vfork` | Handler present |
| 59 | `execve` | `linux_execve` | Handler present |
| 60 | `exit` | `linux_exit` | Handler present |
| 61 | `wait4` | `linux_wait4` | Handler present |
| 62 | `kill` | `linux_kill` | Handler present |
| 63 | `uname` | `linux_newuname` | Handler present |
| 64 | `semget` | `linux_semget` | Handler present |
| 65 | `semop` | `sys_semop` | Handler present |
| 66 | `semctl` | `linux_semctl` | Handler present |
| 67 | `shmdt` | `linux_shmdt` | Handler present |
| 68 | `msgget` | `linux_msgget` | Handler present |
| 69 | `msgsnd` | `linux_msgsnd` | Handler present |
| 70 | `msgrcv` | `linux_msgrcv` | Handler present |
| 71 | `msgctl` | `linux_msgctl` | Handler present |
| 72 | `fcntl` | `linux_fcntl` | Handler present; Command/flag coverage varies; handler presence does not mean all operations work |
| 73 | `flock` | `sys_flock` | Handler present |
| 74 | `fsync` | `sys_fsync` | Handler present |
| 75 | `fdatasync` | `linux_fdatasync` | Handler present |
| 76 | `truncate` | `linux_truncate` | Handler present |
| 77 | `ftruncate` | `linux_ftruncate` | Handler present |
| 78 | `getdents` | `linux_getdents` | Handler present |
| 79 | `getcwd` | `linux_getcwd` | Handler present |
| 80 | `chdir` | `linux_chdir` | Handler present |
| 81 | `fchdir` | `sys_fchdir` | Handler present |
| 82 | `rename` | `linux_rename` | Handler present |
| 83 | `mkdir` | `linux_mkdir` | Handler present |
| 84 | `rmdir` | `linux_rmdir` | Handler present |
| 85 | `creat` | `linux_creat` | Handler present |
| 86 | `link` | `linux_link` | Handler present |
| 87 | `unlink` | `linux_unlink` | Handler present |
| 88 | `symlink` | `linux_symlink` | Handler present |
| 89 | `readlink` | `linux_readlink` | Handler present |
| 90 | `chmod` | `linux_chmod` | Handler present |
| 91 | `fchmod` | `sys_fchmod` | Handler present |
| 92 | `chown` | `linux_chown` | Handler present |
| 93 | `fchown` | `sys_fchown` | Handler present |
| 94 | `lchown` | `linux_lchown` | Handler present |
| 95 | `umask` | `sys_umask` | Handler present |
| 96 | `gettimeofday` | `sys_gettimeofday` | Handler present |
| 97 | `getrlimit` | `linux_getrlimit` | Handler present |
| 98 | `getrusage` | `sys_getrusage` | Handler present |
| 99 | `sysinfo` | `linux_sysinfo` | Handler present |
| 100 | `times` | `linux_times` | Handler present |
| 101 | `ptrace` | `linux_ptrace` | Handler present; Command/flag coverage varies; handler presence does not mean all operations work |
| 102 | `getuid` | `linux_getuid` | Handler present |
| 103 | `syslog` | `linux_syslog` | Handler present |
| 104 | `getgid` | `linux_getgid` | Handler present |
| 105 | `setuid` | `sys_setuid` | Handler present |
| 106 | `setgid` | `sys_setgid` | Handler present |
| 107 | `geteuid` | `sys_geteuid` | Handler present |
| 108 | `getegid` | `sys_getegid` | Handler present |
| 109 | `setpgid` | `sys_setpgid` | Handler present |
| 110 | `getppid` | `linux_getppid` | Handler present |
| 111 | `getpgrp` | `sys_getpgrp` | Handler present |
| 112 | `setsid` | `sys_setsid` | Handler present |
| 113 | `setreuid` | `sys_setreuid` | Handler present |
| 114 | `setregid` | `sys_setregid` | Handler present |
| 115 | `getgroups` | `linux_getgroups` | Handler present |
| 116 | `setgroups` | `linux_setgroups` | Handler present |
| 117 | `setresuid` | `sys_setresuid` | Handler present |
| 118 | `getresuid` | `sys_getresuid` | Handler present |
| 119 | `setresgid` | `sys_setresgid` | Handler present |
| 120 | `getresgid` | `sys_getresgid` | Handler present |
| 121 | `getpgid` | `sys_getpgid` | Handler present |
| 122 | `setfsuid` | `linux_setfsuid` | Handler present |
| 123 | `setfsgid` | `linux_setfsgid` | Handler present |
| 124 | `getsid` | `linux_getsid` | Handler present |
| 125 | `capget` | `linux_capget` | Handler present |
| 126 | `capset` | `linux_capset` | Handler present |
| 127 | `rt_sigpending` | `linux_rt_sigpending` | Handler present |
| 128 | `rt_sigtimedwait` | `linux_rt_sigtimedwait` | Handler present |
| 129 | `rt_sigqueueinfo` | `linux_rt_sigqueueinfo` | Handler present |
| 130 | `rt_sigsuspend` | `linux_rt_sigsuspend` | Handler present |
| 131 | `sigaltstack` | `linux_sigaltstack` | Handler present |
| 132 | `utime` | `linux_utime` | Handler present |
| 133 | `mknod` | `linux_mknod` | Handler present |
| 134 | `uselib` | `nosys` | Historical: unimplemented |
| 135 | `personality` | `linux_personality` | Handler present |
| 136 | `ustat` | `linux_ustat` | Handler present |
| 137 | `statfs` | `linux_statfs` | Handler present |
| 138 | `fstatfs` | `linux_fstatfs` | Handler present |
| 139 | `sysfs` | `linux_sysfs` | Handler present |
| 140 | `getpriority` | `linux_getpriority` | Handler present |
| 141 | `setpriority` | `sys_setpriority` | Handler present |
| 142 | `sched_setparam` | `linux_sched_setparam` | Handler present |
| 143 | `sched_getparam` | `linux_sched_getparam` | Handler present |
| 144 | `sched_setscheduler` | `linux_sched_setscheduler` | Handler present |
| 145 | `sched_getscheduler` | `linux_sched_getscheduler` | Handler present |
| 146 | `sched_get_priority_max` | `linux_sched_get_priority_max` | Handler present |
| 147 | `sched_get_priority_min` | `linux_sched_get_priority_min` | Handler present |
| 148 | `sched_rr_get_interval` | `linux_sched_rr_get_interval` | Handler present |
| 149 | `mlock` | `sys_mlock` | Handler present |
| 150 | `munlock` | `sys_munlock` | Handler present |
| 151 | `mlockall` | `linux_mlockall` | Handler present |
| 152 | `munlockall` | `sys_munlockall` | Handler present |
| 153 | `vhangup` | `linux_vhangup` | Handler present |
| 154 | `modify_ldt` | `linux_modify_ldt` | Handler present |
| 155 | `pivot_root` | `linux_pivot_root` | Missing: ENOSYS stub |
| 156 | `_sysctl` | `linux_sysctl` | Handler present |
| 157 | `prctl` | `linux_prctl` | Handler present; Command/flag coverage varies; handler presence does not mean all operations work |
| 158 | `arch_prctl` | `linux_arch_prctl` | Handler present |
| 159 | `adjtimex` | `linux_adjtimex` | Handler present |
| 160 | `setrlimit` | `linux_setrlimit` | Handler present |
| 161 | `chroot` | `sys_chroot` | Handler present |
| 162 | `sync` | `sys_sync` | Handler present |
| 163 | `acct` | `sys_acct` | Handler present |
| 164 | `settimeofday` | `sys_settimeofday` | Handler present |
| 165 | `mount` | `linux_mount` | Handler present |
| 166 | `umount2` | `linux_umount` | Handler present |
| 167 | `swapon` | `linux_swapon` | Handler present |
| 168 | `swapoff` | `linux_swapoff` | Handler present |
| 169 | `reboot` | `linux_reboot` | Handler present |
| 170 | `sethostname` | `linux_sethostname` | Handler present |
| 171 | `setdomainname` | `linux_setdomainname` | Handler present |
| 172 | `iopl` | `linux_iopl` | Handler present |
| 173 | `ioperm` | `linux_ioperm` | Handler present |
| 174 | `create_module` | `nosys` | Historical: unimplemented |
| 175 | `init_module` | `linux_init_module` | Missing: ENOSYS stub |
| 176 | `delete_module` | `linux_delete_module` | Missing: ENOSYS stub |
| 177 | `get_kernel_syms` | `nosys` | Historical: unimplemented |
| 178 | `query_module` | `nosys` | Historical: unimplemented |
| 179 | `quotactl` | `linux_quotactl` | Handler present; Partial: global quota sync only |
| 180 | `nfsservctl` | `nosys` | Historical: unimplemented |
| 181 | `getpmsg` | `nosys` | Historical: unimplemented |
| 182 | `putpmsg` | `nosys` | Historical: unimplemented |
| 183 | `afs_syscall` | `nosys` | Historical: unimplemented |
| 184 | `tuxcall` | `nosys` | Historical: unimplemented |
| 185 | `security` | `nosys` | Historical: unimplemented |
| 186 | `gettid` | `linux_gettid` | Handler present |
| 187 | `readahead` | `linux_readahead` | Handler present |
| 188 | `setxattr` | `linux_setxattr` | Handler present |
| 189 | `lsetxattr` | `linux_lsetxattr` | Handler present |
| 190 | `fsetxattr` | `linux_fsetxattr` | Handler present |
| 191 | `getxattr` | `linux_getxattr` | Handler present |
| 192 | `lgetxattr` | `linux_lgetxattr` | Handler present |
| 193 | `fgetxattr` | `linux_fgetxattr` | Handler present |
| 194 | `listxattr` | `linux_listxattr` | Handler present |
| 195 | `llistxattr` | `linux_llistxattr` | Handler present |
| 196 | `flistxattr` | `linux_flistxattr` | Handler present |
| 197 | `removexattr` | `linux_removexattr` | Handler present |
| 198 | `lremovexattr` | `linux_lremovexattr` | Handler present |
| 199 | `fremovexattr` | `linux_fremovexattr` | Handler present |
| 200 | `tkill` | `linux_tkill` | Handler present |
| 201 | `time` | `linux_time` | Handler present |
| 202 | `futex` | `linux_sys_futex` | Handler present; Command/flag coverage varies; handler presence does not mean all operations work |
| 203 | `sched_setaffinity` | `linux_sched_setaffinity` | Handler present |
| 204 | `sched_getaffinity` | `linux_sched_getaffinity` | Handler present |
| 205 | `set_thread_area` | `nosys` | Historical: unimplemented |
| 206 | `io_setup` | `linux_io_setup` | Handler present; Partial legacy AIO; option/cancellation/lifecycle gaps remain |
| 207 | `io_destroy` | `linux_io_destroy` | Handler present; Partial legacy AIO; option/cancellation/lifecycle gaps remain |
| 208 | `io_getevents` | `linux_io_getevents` | Handler present; Partial legacy AIO; option/cancellation/lifecycle gaps remain |
| 209 | `io_submit` | `linux_io_submit` | Handler present; Partial legacy AIO; option/cancellation/lifecycle gaps remain |
| 210 | `io_cancel` | `linux_io_cancel` | Handler present; Partial legacy AIO; option/cancellation/lifecycle gaps remain |
| 211 | `get_thread_area` | `nosys` | Historical: unimplemented |
| 212 | `lookup_dcookie` | `linux_lookup_dcookie` | Missing: ENOSYS stub |
| 213 | `epoll_create` | `linux_epoll_create` | Handler present |
| 214 | `epoll_ctl_old` | `nosys` | Historical: unimplemented |
| 215 | `epoll_wait_old` | `nosys` | Historical: unimplemented |
| 216 | `remap_file_pages` | `linux_remap_file_pages` | Handler present |
| 217 | `getdents64` | `linux_getdents64` | Handler present |
| 218 | `set_tid_address` | `linux_set_tid_address` | Handler present |
| 219 | `restart_syscall` | `linux_restart_syscall` | Handler present |
| 220 | `semtimedop` | `linux_semtimedop` | Handler present |
| 221 | `fadvise64` | `linux_fadvise64` | Handler present |
| 222 | `timer_create` | `linux_timer_create` | Handler present |
| 223 | `timer_settime` | `linux_timer_settime` | Handler present |
| 224 | `timer_gettime` | `linux_timer_gettime` | Handler present |
| 225 | `timer_getoverrun` | `linux_timer_getoverrun` | Handler present |
| 226 | `timer_delete` | `linux_timer_delete` | Handler present |
| 227 | `clock_settime` | `linux_clock_settime` | Handler present |
| 228 | `clock_gettime` | `linux_clock_gettime` | Handler present |
| 229 | `clock_getres` | `linux_clock_getres` | Handler present |
| 230 | `clock_nanosleep` | `linux_clock_nanosleep` | Handler present |
| 231 | `exit_group` | `linux_exit_group` | Handler present |
| 232 | `epoll_wait` | `linux_epoll_wait` | Handler present |
| 233 | `epoll_ctl` | `linux_epoll_ctl` | Handler present |
| 234 | `tgkill` | `linux_tgkill` | Handler present |
| 235 | `utimes` | `linux_utimes` | Handler present |
| 236 | `vserver` | `nosys` | Historical: unimplemented |
| 237 | `mbind` | `linux_mbind` | Handler present; Validation/success path without requested policy enforcement or page migration; not full semantic implementation |
| 238 | `set_mempolicy` | `linux_set_mempolicy` | Handler present; Validation/success path without requested policy enforcement or page migration; not full semantic implementation |
| 239 | `get_mempolicy` | `linux_get_mempolicy` | Handler present; Limited NUMA reporting/behavior; see coverage and linux_misc.c |
| 240 | `mq_open` | `linux_mq_open` | Handler present |
| 241 | `mq_unlink` | `linux_mq_unlink` | Handler present |
| 242 | `mq_timedsend` | `linux_mq_timedsend` | Handler present |
| 243 | `mq_timedreceive` | `linux_mq_timedreceive` | Handler present |
| 244 | `mq_notify` | `linux_mq_notify` | Handler present |
| 245 | `mq_getsetattr` | `linux_mq_getsetattr` | Handler present |
| 246 | `kexec_load` | `linux_kexec_load` | Missing: ENOSYS stub |
| 247 | `waitid` | `linux_waitid` | Handler present |
| 248 | `add_key` | `linux_add_key` | Missing: ENOSYS stub |
| 249 | `request_key` | `linux_request_key` | Missing: ENOSYS stub |
| 250 | `keyctl` | `linux_keyctl` | Missing: ENOSYS stub |
| 251 | `ioprio_set` | `linux_ioprio_set` | Handler present |
| 252 | `ioprio_get` | `linux_ioprio_get` | Handler present |
| 253 | `inotify_init` | `linux_inotify_init` | Handler present |
| 254 | `inotify_add_watch` | `linux_inotify_add_watch` | Handler present |
| 255 | `inotify_rm_watch` | `linux_inotify_rm_watch` | Handler present |
| 256 | `migrate_pages` | `linux_migrate_pages` | Handler present; Validation/success path without requested policy enforcement or page migration; not full semantic implementation |
| 257 | `openat` | `linux_openat` | Handler present |
| 258 | `mkdirat` | `linux_mkdirat` | Handler present |
| 259 | `mknodat` | `linux_mknodat` | Handler present |
| 260 | `fchownat` | `linux_fchownat` | Handler present |
| 261 | `futimesat` | `linux_futimesat` | Handler present |
| 262 | `newfstatat` | `linux_newfstatat` | Handler present |
| 263 | `unlinkat` | `linux_unlinkat` | Handler present |
| 264 | `renameat` | `linux_renameat` | Handler present |
| 265 | `linkat` | `linux_linkat` | Handler present |
| 266 | `symlinkat` | `linux_symlinkat` | Handler present |
| 267 | `readlinkat` | `linux_readlinkat` | Handler present |
| 268 | `fchmodat` | `linux_fchmodat` | Handler present |
| 269 | `faccessat` | `linux_faccessat` | Handler present |
| 270 | `pselect6` | `linux_pselect6` | Handler present |
| 271 | `ppoll` | `linux_ppoll` | Handler present |
| 272 | `unshare` | `linux_unshare` | Handler present; Partial: single-threaded CLONE_FS only |
| 273 | `set_robust_list` | `linux_set_robust_list` | Handler present |
| 274 | `get_robust_list` | `linux_get_robust_list` | Handler present |
| 275 | `splice` | `linux_splice` | Handler present |
| 276 | `tee` | `linux_tee` | Handler present |
| 277 | `sync_file_range` | `linux_sync_file_range` | Handler present |
| 278 | `vmsplice` | `linux_vmsplice` | Handler present |
| 279 | `move_pages` | `linux_move_pages` | Handler present; Limited NUMA reporting/behavior; see coverage and linux_misc.c |
| 280 | `utimensat` | `linux_utimensat` | Handler present |
| 281 | `epoll_pwait` | `linux_epoll_pwait` | Handler present |
| 282 | `signalfd` | `linux_signalfd` | Handler present |
| 283 | `timerfd_create` | `linux_timerfd_create` | Handler present |
| 284 | `eventfd` | `linux_eventfd` | Handler present |
| 285 | `fallocate` | `linux_fallocate` | Handler present; Partial: allocation and hole punch; other modes rejected |
| 286 | `timerfd_settime` | `linux_timerfd_settime` | Handler present |
| 287 | `timerfd_gettime` | `linux_timerfd_gettime` | Handler present |
| 288 | `accept4` | `linux_accept4` | Handler present |
| 289 | `signalfd4` | `linux_signalfd4` | Handler present |
| 290 | `eventfd2` | `linux_eventfd2` | Handler present |
| 291 | `epoll_create1` | `linux_epoll_create1` | Handler present |
| 292 | `dup3` | `linux_dup3` | Handler present |
| 293 | `pipe2` | `linux_pipe2` | Handler present |
| 294 | `inotify_init1` | `linux_inotify_init1` | Handler present |
| 295 | `preadv` | `linux_preadv` | Handler present |
| 296 | `pwritev` | `linux_pwritev` | Handler present |
| 297 | `rt_tgsigqueueinfo` | `linux_rt_tgsigqueueinfo` | Handler present |
| 298 | `perf_event_open` | `linux_perf_event_open` | Partial: current-thread software counters |
| 299 | `recvmmsg` | `linux_recvmmsg` | Handler present |
| 300 | `fanotify_init` | `linux_fanotify_init` | Missing: ENOSYS stub |
| 301 | `fanotify_mark` | `linux_fanotify_mark` | Missing: ENOSYS stub |
| 302 | `prlimit64` | `linux_prlimit64` | Handler present |
| 303 | `name_to_handle_at` | `linux_name_to_handle_at` | Handler present |
| 304 | `open_by_handle_at` | `linux_open_by_handle_at` | Handler present |
| 305 | `clock_adjtime` | `linux_clock_adjtime` | Handler present |
| 306 | `syncfs` | `linux_syncfs` | Handler present |
| 307 | `sendmmsg` | `linux_sendmmsg` | Handler present |
| 308 | `setns` | `linux_setns` | Missing: ENOSYS stub |
| 309 | `getcpu` | `linux_getcpu` | Handler present |
| 310 | `process_vm_readv` | `linux_process_vm_readv` | Handler present |
| 311 | `process_vm_writev` | `linux_process_vm_writev` | Handler present |
| 312 | `kcmp` | `linux_kcmp` | Handler present |
| 313 | `finit_module` | `linux_finit_module` | Missing: ENOSYS stub |
| 314 | `sched_setattr` | `linux_sched_setattr` | Handler present |
| 315 | `sched_getattr` | `linux_sched_getattr` | Handler present |
| 316 | `renameat2` | `linux_renameat2` | Handler present |
| 317 | `seccomp` | `linux_seccomp` | Missing: reject-only; No filter enforcement |
| 318 | `getrandom` | `linux_getrandom` | Handler present |
| 319 | `memfd_create` | `linux_memfd_create` | Handler present |
| 320 | `kexec_file_load` | `linux_kexec_file_load` | Missing: ENOSYS stub |
| 321 | `bpf` | `linux_bpf` | Missing: ENOSYS stub |
| 322 | `execveat` | `linux_execveat` | Handler present |
| 323 | `userfaultfd` | `linux_userfaultfd` | Missing: ENOSYS stub |
| 324 | `membarrier` | `linux_membarrier` | Handler present |
| 325 | `mlock2` | `linux_mlock2` | Handler present |
| 326 | `copy_file_range` | `linux_copy_file_range` | Handler present |
| 327 | `preadv2` | `linux_preadv2` | Handler present |
| 328 | `pwritev2` | `linux_pwritev2` | Handler present |
| 329 | `pkey_mprotect` | `linux_pkey_mprotect` | Handler present |
| 330 | `pkey_alloc` | `linux_pkey_alloc` | Handler present |
| 331 | `pkey_free` | `linux_pkey_free` | Handler present |
| 332 | `statx` | `linux_statx` | Handler present |
| 333 | `io_pgetevents` | `linux_io_pgetevents` | Handler present; Partial legacy AIO; option/cancellation/lifecycle gaps remain |
| 334 | `rseq` | `linux_rseq` | Handler present; Named amd64 rseq contracts; broader lifecycle/client qualification pending |
| 335 | `uretprobe` | `linux_uretprobe` | Missing: ENOSYS stub |
| 336 | `uprobe` | `linux_uprobe` | Missing: ENOSYS stub |
| 424 | `pidfd_send_signal` | `linux_pidfd_send_signal` | Handler present |
| 425 | `io_uring_setup` | `linux_io_uring_setup` | Handler present |
| 426 | `io_uring_enter` | `linux_io_uring_enter` | Handler present |
| 427 | `io_uring_register` | `linux_io_uring_register` | Handler present |
| 428 | `open_tree` | `linux_open_tree` | Missing: ENOSYS stub |
| 429 | `move_mount` | `linux_move_mount` | Missing: ENOSYS stub |
| 430 | `fsopen` | `linux_fsopen` | Missing: ENOSYS stub |
| 431 | `fsconfig` | `linux_fsconfig` | Missing: ENOSYS stub |
| 432 | `fsmount` | `linux_fsmount` | Missing: ENOSYS stub |
| 433 | `fspick` | `linux_fspick` | Missing: ENOSYS stub |
| 434 | `pidfd_open` | `linux_pidfd_open` | Handler present |
| 435 | `clone3` | `linux_clone3` | Handler present; Command/flag coverage varies; handler presence does not mean all operations work |
| 436 | `close_range` | `linux_close_range` | Handler present |
| 437 | `openat2` | `linux_openat2` | Handler present; Command/flag coverage varies; handler presence does not mean all operations work |
| 438 | `pidfd_getfd` | `linux_pidfd_getfd` | Handler present |
| 439 | `faccessat2` | `linux_faccessat2` | Handler present |
| 440 | `process_madvise` | `linux_process_madvise` | Handler present |
| 441 | `epoll_pwait2` | `linux_epoll_pwait2` | Handler present |
| 442 | `mount_setattr` | `linux_mount_setattr` | Missing: ENOSYS stub |
| 443 | `quotactl_fd` | `linux_quotactl_fd64` | Handler present; Partial: ZFS user/group query, byte hard-limit update and sync |
| 444 | `landlock_create_ruleset` | `linux_landlock_create_ruleset` | Missing: ENOSYS stub |
| 445 | `landlock_add_rule` | `linux_landlock_add_rule` | Missing: ENOSYS stub |
| 446 | `landlock_restrict_self` | `linux_landlock_restrict_self` | Missing: ENOSYS stub |
| 447 | `memfd_secret` | `linux_memfd_secret` | Missing: ENOSYS stub |
| 448 | `process_mrelease` | `linux_process_mrelease` | Missing: ENOSYS stub |
| 449 | `futex_waitv` | `linux_futex_waitv` | Handler present |
| 450 | `set_mempolicy_home_node` | `linux_set_mempolicy_home_node` | Handler present; Validation/success path without requested policy enforcement or page migration; not full semantic implementation |
| 451 | `cachestat` | `linux_cachestat` | Handler present |
| 452 | `fchmodat2` | `linux_fchmodat2` | Handler present |
| 453 | `map_shadow_stack` | `linux_map_shadow_stack` | Missing: ENOSYS stub |
| 454 | `futex_wake` | `linux_futex_wake` | Handler present |
| 455 | `futex_wait` | `linux_futex_wait` | Handler present |
| 456 | `futex_requeue` | `linux_futex_requeue` | Handler present |
| 457 | `statmount` | `linux_statmount` | Handler present; Limited native mount model; no Linux mount namespaces |
| 458 | `listmount` | `linux_listmount` | Handler present; Limited native mount model; no Linux mount namespaces |
| 459 | `lsm_get_self_attr` | `linux_lsm_get_self_attr` | Missing: ENOSYS stub |
| 460 | `lsm_set_self_attr` | `linux_lsm_set_self_attr` | Missing: ENOSYS stub |
| 461 | `lsm_list_modules` | `linux_lsm_list_modules` | Missing: ENOSYS stub |
| 462 | `mseal` | `linux_mseal` | Handler present |
| 463 | `setxattrat` | `linux_setxattrat` | Handler present |
| 464 | `getxattrat` | `linux_getxattrat` | Handler present |
| 465 | `listxattrat` | `linux_listxattrat` | Handler present |
| 466 | `removexattrat` | `linux_removexattrat` | Handler present |
| 467 | `open_tree_attr` | `linux_open_tree_attr` | Missing: ENOSYS stub |
| 468 | `file_getattr` | `linux_file_getattr` | Handler present |
| 469 | `file_setattr` | `linux_file_setattr` | Handler present |
| 470 | `listns` | `linux_listns` | Missing: ENOSYS stub |
| 471 | `rseq_slice_yield` | `linux_rseq_slice_yield` | Missing: ENOSYS stub |
| 472 | `fchroot` | `linux_fchroot` | Handler present |

## Source fingerprints

SHA-256 at review time (later workspace changes require a recount):

```text
5f9c449984a7c7d515661d2d57218ab4c8353bd4404fd73342996f3521bd9584  sys/amd64/linux/syscalls.master
2738a3b3b168114ed3c6f8305cfec36d1f624b5c34e58f8b2dc8273b0fd7f976  sys/amd64/linux/linux_sysent.c
d22625d29ea842647d3252ec925213ccc23405540ba95f883e39c252d1a03300  sys/compat/linux/linux_dummy.c
a5476a26347c9ea7f90c101778fa785928e32284111f4e53ce740b639bcaf2e6  sys/amd64/linux/linux_dummy_machdep.c
972ebdb8e7220487eeb294f436f6f5fe9169760a9cc09ead243c003c81b7b074  sys/x86/linux/linux_dummy_x86.c
a6859e1f8ab5244e748bf4f6e1a994ee9c30e075112875604c86e2fc5627a824  sys/compat/linux/linux_misc.c
```
