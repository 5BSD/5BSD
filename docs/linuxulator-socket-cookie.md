# Linux64 SO_COOKIE

Status: Linux-reference, focused FreeBSD VM and Python socket-client checks
pass. The full amd64 ZFS-root regression gate also passes. No host installation.

Scope: amd64 Linux64 `getsockopt(fd, SOL_SOCKET, SO_COOKIE, ...)` (option 57).
Linux32 and arm64 dispatch remain unchanged. The result is an opaque, nonzero
64-bit identity shared by all descriptors referring to the same socket.
Different live sockets have different identities. It is not SO_MARK or the
native writable SO_USER_COOKIE packet tag.

Linux v6.18 [socket options](https://github.com/torvalds/linux/blob/v6.18/net/core/sock.c)
require at least eight output bytes, return eight as optlen, and reject
negative/short lengths. Invalid descriptors, nonsockets and copy faults must
be reported without leaking file references. Setting SO_COOKIE remains
unsupported. Copies to oversized buffers must not overwrite the tail.

The backend is the native socket's existing generation identity, immutable
while a reference keeps that socket alive. A held socket lookup enforces
CAP_GETSOCKOPT; the Linux frontend owns option numbering, length policy and
copyout. No new native syscall, socket storage, or io_uring change is needed.

Passing checks: Unix/IPv4/IPv6 sockets, stable repeated/dup/fork/exec access,
SCM_RIGHTS transfer, distinct socketpair endpoints, close/fd reuse and churn,
invalid descriptors/types/lengths, read-only/guard-page/bad-pointer outputs,
unprivileged access, and native-created descriptors with allowed/denied
Capsicum rights. All probes run only in disposable Linux and ZFS-root FreeBSD
VMs. Artifact directory: `/tmp/linuxulator-cookie-20260922`.


Evidence under that directory:

- `oracle1.console.log`: Linux 6.18.35, six cases as root and unprivileged.
- `focus1.console.log`: three rounds, 24 case/suite records, including nine
  native descriptor-right/capability-mode combinations; healthy ZFS and clean
  shutdown.
- `client.console.log`: Python 3.14.7 socket identity/dup/close checks inside
  GDB, GDB 16.3 target execution and register editing, and all 90 ptrace
  regressions. Healthy ZFS and clean shutdown.
- `full1-run/results.json`: the combined build passes all 24 cookie records,
  90 ptrace checks, 449 main io_uring cases, 1,098 shared-option checks and
  the remaining syscall suites. No diagnostics/nonzero results, zero final
  tracked resources, healthy ZFS, synced buffers and clean poweroff.
- `manifest.json`, `source-inputs.json`, `source-snapshot/`, `task.patch`:
  frozen input/artifact hashes and this batch's isolated change. The kernel
  and common modules come from the debugger-options batch; linux64.ko is
  rebuilt with the socket change.

No new syscall number is added: this extends getsockopt. The full regression
image excludes the optional Alpine runtime used by the focused client image.
