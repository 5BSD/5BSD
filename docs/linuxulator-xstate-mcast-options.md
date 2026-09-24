# Linux64 XSAVE writes and multicast source-filter options

Follow-up: [peer names, mixed multicast deltas and process ptrace events](linuxulator-peer-events-options.md)
records the implemented amd64 subset and VM evidence. Earlier missing-option
entries below are superseded for that subset; full Linux thread tracing remains
unfinished. SO_COOKIE was already implemented before that follow-up.

This batch extends existing amd64 Linux64 `ptrace`, `setsockopt` and
`getsockopt` handlers. It adds no syscall numbers or Linux32 support.

## XSAVE writes

`PTRACE_SETREGSET(NT_X86_XSTATE)` accepts a complete, standard-format XSAVE
image for the features enabled by the native kernel. The adapter validates
XSTATE_BV, XCOMP_BV, reserved header words and MXCSR before calling the existing
native FPU setter. Linux software metadata at bytes 464–511 is ignored.
Unsupported feature bits and compacted images return EINVAL; an aligned short
image returns EFAULT; oversized aligned iovecs are clamped to the native image
size. Without XSAVE, GETREGSET and SETREGSET return ENODEV. The existing held
tracee access path supplies authorization, stop-state checks and fault handling.
An iovec writeback fault can occur after register state has been committed,
matching the Linux reference.

Tests cover readback, actual AVX state after resumption, invalid headers and
MXCSR, absent-component initialization, input faults, iovec writeback faults,
metadata, lengths, and unprivileged tracing after a credential-reset exec.
There are no changes to native FPU or ptrace machinery for this option.
AVX-512, AMX and every possible hardware XSAVE configuration are not qualified.

## Multicast full-state filters

The supported combinations are IP_MSFILTER on AF_INET sockets and
MCAST_MSFILTER on AF_INET or AF_INET6 sockets at the matching protocol level.
Both GET and SET translate Linux's inline vector into the native pointer-based
request, including the different INCLUDE/EXCLUDE values and sockaddr layouts.
INCLUDE with no sources leaves the membership. EXCLUDE with no sources clears
old sources and accepts all senders. GET reports the full source count while
copying only the requested number of entries. The tests also check Linux's
output ordering when an output pointer faults.

The adapter holds the socket file for the entire operation and checks its
GETSOCKOPT/SETSOCKOPT descriptor rights. SET preserves MAC authorization.
Native capability-mode syscall rejection remains unchanged. Input copies are
bounded at 128 KiB and 1024 sources; native multicast limits can reject smaller
requests. No network namespace emulation is added.

The shared changes are confined to the IPv4/IPv6 multicast implementation and
its per-membership structures:

- Support kernel-space nested vectors when `sopt_td` is NULL.
- Copy input before retaining membership pointers, hold an interface reference,
  and keep copy faults from modifying pending filter state.
- Clear old sources on empty replacement.
- Retain a canonical full-state vector for GET, preserving source order and
  duplicates while the existing tree enforces packet filtering. Release it on
  replacement, incremental mutation or membership destruction.
- Correct native IPv6 EXCLUDE filtering, which previously passed a source
  explicitly present in the exclusion list.

Packet tests exercise both INCLUDE and EXCLUDE, matching and nonmatching
sources, and empty EXCLUDE on IPv4 and IPv6. Additional tests cover replacement,
leave/rejoin, partial queries, invalid inputs, faults, fork/dup lifetime,
duplicate/order preservation, default interfaces and concurrent updates.
The native probe checks both native APIs, failed-copy rollback, empty filters,
descriptor-right removal and capability-mode rejection across Linux exec.

This is a bounded subset. IPv4 options on dual-stack AF_INET6 sockets are not
supported; the preexisting IPv4 membership operations on those sockets are
also missing. Native source-address validation and resource limits still apply.
Link-local/scope combinations, interface removal races and raw sockets are not
qualified. Mixing incremental source operations with full-state operations
invalidates the retained vector: packet-filter semantics remain native, but
Linux source-list order and duplicate multiplicity across that mixture are not
claimed. The native GET path can still return sources in tree order for
memberships last changed through an incremental API.

## Recorded io_uring exception

The main 450-case io_uring matrix reported one failure:
`ioprio_send_zc_fixed_vectorized`, exit status 6. The diagnostic runs already
started when the user requested note-only handling completed on both the
previous build and this candidate: 11 of 100 attempts failed in each VM.
Both completion records were present, but the test's immediate nonblocking
TCP read returned EAGAIN. This reproduces an existing timing-sensitive test
issue. No io_uring implementation or repository test change was made for it.
The logs are `candidate-recheck.console.log` and `baseline-recheck.console.log`.
The full gate must remain reported as **not fully passing** because of this
exception; it does not invalidate the separately successful XSAVE/multicast
matrices. The user requested that io_uring issues only be noted.

## Validation and evidence

All syscall execution took place in disposable VMs, never on the host.
Artifacts are under `/tmp/linuxulator-xstate-mcast-20260922/`:

- `oracle7.console.log`: Linux 6.18.35, seven XSAVE groups as root and an
  unprivileged user (14 executions).
- `oracle6.console.log`: Linux reference multicast matrix, including packet
  delivery, concurrent updates and the dual-stack behavior outside this subset.
- `oracle-no-xsave.console.log`: Linux ENODEV behavior without XSAVE.
- `focus5.console.log`: FreeBSD focused matrix, including root/unprivileged
  multicast delivery and four native descriptor-right/capmode scenarios.
- `client2.console.log`: GDB 16.3 writes both halves of YMM0; the resumed target
  verifies the values and exits normally. GDB's existing ret-to-NX SIGBUS
  warning remains; complete debugger compatibility is not claimed.
- `no-xsave3.console.log`: final module on a FreeBSD CPU without XSAVE.
- `config-checks/results.json`: compile checks with IPv4 only, IPv6 only and
  neither protocol, with absent-family route symbols checked.
- `full3-run/`: full amd64 GENERIC INVARIANTS/WITNESS ZFS-root regression gate;
  completed with the single io_uring exception recorded above. All 111 new
  XSAVE/multicast executions and the other recorded regressions passed.
  The pool remained healthy and final request/file/page counters returned to
  their initial values; there were no panic or lock-order diagnostics.

The full gate requires 42 XSAVE, 66 multicast and three native multicast result
records, in addition to all existing regressions. Each multicast execution
covers the IPv4 legacy, IPv4 group and IPv6 group forms. It uses two vCPUs,
2 GiB RAM and a restricted virtual Ethernet interface for packet delivery.
`source-snapshot/`, `source-inputs.json`, build logs and the final manifest
identify the composed working tree and staged artifacts. Unrelated existing
changes are included in the composed test kernel, not claimed as this batch.
