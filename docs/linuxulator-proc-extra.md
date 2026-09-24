# Linux64 procfs task links, descriptor state and socket tables

Scope: amd64 Linux64. No Linux32 qualification or targeted io_uring work.
These changes extend the procfs/filesystem work described in
[the handoff](linuxulator-filesystems-handoff.md). They do not constitute
application or production-release certification.

## Interfaces

- `/proc/PID/task/TID/{cwd,root,exe}` uses the existing procfs visibility,
  debugging permission, magic-link resolution and thread-lifetime checks.
- `fdinfo` adds eventfd counter/semaphore mode, signalfd signal mask, timerfd
  clock/ticks/settime flags/remaining time/interval, and epoll interests.
- `/proc/net/{tcp,tcp6,udp,udp6,unix}` supplies native socket snapshots in
  Linux column layouts. Socket inode identity matches Linux64 fstat/statx,
  fdinfo and `socket:[inode]` links. Native socket fstat is unchanged.

Native socket generation is exported in previously reserved xsocket space;
structure size is preserved. kinfo_file gains timerfd and signalfd metadata
without expanding its existing union. Deploy matching kernel and modules:
linprocfs requires the new kernel snapshot helper.

## Hardening

Epoll fdinfo copies only descriptor identity, filter and Linux interest/data
metadata under the kqueue lock. Allocation happens outside the lock. It avoids
filter callbacks, pathname collection and process descriptor lookups. The
snapshot retries growth at most four times, caps allocation at 128 MiB and
returns an error rather than silently truncating. Sorting and adjacent
coalescing replace quadratic duplicate scans. Output streams through pseudofs,
so the former fixed output-buffer ceiling does not truncate large tables.

Eventfd, timerfd and signalfd state is copied under the owning object's lock.
EPOLLWAKEUP remains an unsupported power-management hint and is omitted from
reported interests; ordinary masks and 64-bit user data are preserved,
including zero-event registrations. Inotify link text uses `anon_inode:inotify`.

Network tables use native credential-filtered PCB sysctls in the reader's VNET.
Snapshots have bounded allocation/retry and record-length validation. Kernel
socket and PCB pointers are never formatted. A jail fixture inherits host
socket descriptors, enters a new VNET, requires those sockets to be absent
from its tables, and verifies that its own IPv4/IPv6/Unix sockets are visible.

## Tests

`tests/sys/kern/linux_proc_views.c` includes tasklinks, fdextra, fdscale and
sockettables. Cases run as root and an unprivileged user. The scale case uses
128 dual-filter interests with concurrent delete/add and user-data changes,
checks individual reads for valid, unique entries, then requires the complete stable
table and removal of all entries after descriptor close. Procfs output can
change between separate reads; it is not a transaction across read calls.

`linux_proc_net_jail.c` is a native guest fixture, not a host test.
`guest-proc-stress.sh` adds repeated VNET isolation and concurrent new cases to
the existing credential, descriptor, thread, forced-unmount and offset checks.
Timer tests cover disarmed absolute timers, expiration counts and consumption.
An additional 64 unprivileged exec/exit races per guest cover stale fdinfo reads.
They accept ENXIO from the native dead-vnode read handler after process exit;
a diagnostic guest reproduced that result on iteration 46.
The VM controller requires exact inventories and rejects kernel diagnostics.
The Python/GDB client additionally checks real socket/epoll consumers and task
links. The same unbranded Linux probe is also run against a Linux guest.

Artifacts: `/tmp/linuxulator-proc-extra-20260922`. Final results are recorded
in its qualification manifest; intermediate failures do not qualify.

## Compatibility limits

- TCP timer/retransmit/timeout columns and Unix reference counts are currently
  zero placeholders. Native queue byte counts are not Linux skb accounting.
  TIME_WAIT and SYN-cache entries without a live socket may be absent.
- These are `/proc/net` views of the reader's VNET, not `/proc/PID/net` network
  namespace views. No new Linux network namespace implementation is provided.
- Epoll output contains tfd/events/data; modern Linux's additional target
  position/device/inode fields and eventfd-id are not supplied. Native kqueues
  inherited into Linux are not distinguished from epoll descriptors.
- Multi-filter epoll updates use the existing emulator operations and are not
  an atomic transaction with procfs reads. Bounded snapshot retries can return
  EAGAIN during continuous growth.
- Existing deleted-path, anonymous-pipe reopening, arbitrary chroot mount-root
  presentation and native SUGID restrictions remain.

References: [Linux fdinfo](https://man7.org/linux/man-pages/man5/proc_pid_fdinfo.5.html)
and [TCP proc tables](https://docs.kernel.org/networking/proc_net_tcp.html).

## Final qualification — 2026-09-23

All required gates passed with matching kernel/modules:

| Gate | Passing checks |
| --- | ---: |
| Single-CPU and 4-vCPU/SMT focused, stress, security, filesystem and reload gates | 1,606 |
| Broad syscall regressions | 1,184 |
| Linux reference guest | 44 |
| Real Linux Python/GDB client | 8 |

The two focused guests each completed 120 proc cases, 512 concurrent cases,
64 exec/exit races, four native security checks, eight forced unmounts, three
VNET isolation checks, 87 filesystem checks, four FUSE checks and the common
module reload. Both shut down cleanly, with healthy ZFS and no panic, fatal
trap, WITNESS lock-order or non-sleepable-lock diagnostics.

Compile-time ABI checks confirm unchanged amd64 sizes: kinfo_file 1,392 bytes
and xsocket 240 bytes. Final evidence is in `manifest.json`, `source-hashes.json`,
`binary-hashes.json`, `task.patch`, `release-up/`, `release-smp/`,
`regression-final-results.json`, `oracle-release.console.log` and
`client-final.console.log` under the artifact directory. Superseded VM images
were removed; logs and final images remain. No host kernel was installed.
