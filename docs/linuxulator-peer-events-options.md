# Linux64 peer names, multicast deltas and process ptrace events

Follow-up: [pending signals, tracing reattach and multicast mode transitions](linuxulator-signal-modes-options.md)
records the next amd64 batch. Its named contracts supersede the corresponding
remaining-option entries below.

Scope: amd64 Linux64 only. This batch adds options to existing calls; it adds
no syscall numbers and no Linux32 support. SO_COOKIE was already implemented
by the preceding batch and is rerun here. io_uring implementation work belongs
to a separate effort.

## Contracts and tests

| Interface | Implemented behavior | Named tests |
|---|---|---|
| getsockopt(SOL_SOCKET, SO_PEERNAME) | Connected IPv4/IPv6 TCP/UDP and Unix peers; Linux address conversion; requested prefix lengths including zero; reject a length greater than the actual address and preserve the requested length | `linux_socket_peername`: inet4, inet6, local, pathname, state, faults, lifetime |
| SO_PEERNAME access | Held socket reference, CAP_GETSOCKOPT and CAP_GETPEERNAME required; invalid descriptors, connection state, signed lengths, read-only/guard-page outputs; dup/fork/reuse | `linux_socket_peername_caps` native supervisor/Linux probe: full rights, missing each right, capability mode; state, faults, lifetime above |
| IPv4/IPv6 full-state and incremental multicast filters | Preserve insertion order and duplicate entries when mixing full-state replacement with source add/drop/block/unblock; remove one duplicate at a time; retain effective filtering until its last occurrence is removed; leave membership when the last INCLUDE source is removed | `linux_mcast_filter`: mixed, mixed_delivery, mixed_churn, plus the preceding roundtrip, replace, leave, lengths, invalid, faults, lifetime, duplicates, delivery, interfaces, churn groups |
| ptrace SETOPTIONS | Options belong to the tracee process; replace options atomically, reject unknown bits, select process fork/vfork/clone following; preserve syscall tracing options across option replacement | `linux_ptrace_events`: selective, isolation, fork, vfork, clone |
| ptrace process events | FORK, VFORK, process CLONE, EXEC, VFORK_DONE and EXIT stop encoding; GETEVENTMSG and event GETSIGINFO; options inherited by automatically attached processes | exec, fork, vfork, clone, exit, signal, vfork_done |
| ptrace stop/resume and wait | CONT/SINGLESTEP clear syscall-stop mode for Linux callers; TRACESYSGOOD applies to syscall stops; wait4/waitid translate event status; pre-exit register inspection | isolation, waitid, exit; existing register/debugger suites |
| Native regressions | Native multicast duplicate removal and rejoin; unchanged default tracing behavior plus opt-in final-process exit stop | `linux_mcast_native`, `ptrace_exit_native`; existing native ptrace tests |

SO_PEERNAME has no setters, persistent allocation, blocking operation or
deadline. Its lifetime tests repeat descriptor/fork operations 64 times.
Multicast tests include actual UDP delivery, failed operations without state
mutation, unprivileged callers, and two processes repeatedly changing a shared
membership. There is no new timeout ABI. Kernel allocation-failure injection
and deliberate native source-limit exhaustion were not performed.
Ptrace tests include bad options, invalid event-message pointers, target
isolation, unprivileged tracing after exec, normal and signal exit, child
following, and parent/child cleanup. Existing permission and Capsicum tests
remain in the full gate. This is not exhaustive jail or debugger qualification.

## Shared kernel changes

Peer-name translation stays in Linuxulator. IPv6 group-source translation now
passes the native IPv6 sockaddr length rather than sockaddr_storage length.

Native IPv4/IPv6 memberships stage canonical-vector deltas under existing
locks. Commit publishes the prepared vector, rollback frees it, and duplicate
removal prunes the effective source tree only after the final occurrence.
The membership structures change, so rebuild the kernel and matching modules.

Native tracing gains opt-in PTRACE_EXIT before final-process teardown, a
private fork flag to suppress unwanted automatic following, a callback request
holding the process-tree lock for event-mask updates, and private resume
requests which atomically clear syscall-stop flags. Linux option numbering,
event selection and status/message translation remain in Linuxulator. Native
CONT semantics remain unchanged. `ptrace(2)` documents the new native event.

## Deliberate limits

* Ptrace events are **process events**. CLONE_THREAD event delivery, per-thread
  options/stop ownership and complete multithreaded debugger semantics remain
  unfinished. SEIZE, INTERRUPT, LISTEN and a seccomp backend remain separate.
* SIGKILL before the exit stop may bypass TRACEEXIT. Fatal SIGTERM and ordinary
  exits are tested. WNOWAIT event-message queries and detach/reattach option
  reset are not qualified. Existing EXITKILL behavior is unchanged.
* SO_PEERNAME coverage is for live connected peers. Retaining a Unix peer name
  after peer closure and Linux abstract Unix addresses are not qualified.
* Multicast mode switching from an empty EXCLUDE filter to INCLUDE, scoped IPv6
  edge cases, interface removal races, and IPv4 filters on an IPv6 socket remain
  outside this batch. Native source/resource limits and their errors still
  apply; allocation-failure errno parity is not claimed.

## VM evidence

Artifacts are retained in `/tmp/linuxulator-peer-events-20260922/`. Runtime
syscall tests ran only in disposable guests. `source-inputs.json` and
`source-snapshot/` preserve 5,385 build/test inputs; `post-build-drift.json`
was empty when the final gate was staged. Kernel and linux64/linux_common
builds completed successfully (`kernel-final.log`, `linux64-final.log`,
`common-final.log`). Linux and native probes compiled with warnings as errors.

* Linux reference: Alpine 3.24.1 amd64 VM, Linux 6.18.35-0-virt. `oracle7.console.log` passes all 15
  multicast groups (including a reference-only dual-stack group);
  `oracle14.console.log` passes all 20 root/unprivileged process-event cases;
  `oracle13.console.log` passes all 14 root/unprivileged peer-name cases.
* BSD focused qualification: `focus6.console.log` passes 62 Linux cases
  (14 peer, 28 multicast, 20 process event), all four capability modes,
  native exit events, preceding native multicast coverage, and cookie tests.
  The extended native multicast duplicate-removal probe is in the full gate.
* Real clients: `client2.console.log` records Python socket peer-name and
  duplicate-filter packet-delivery checks, plus Linux GDB 16.3 catching fork
  and exec and observing exit status 7. All pass. GDB still emits existing
  executable-path/proc-memory and return-to-NX signal warnings; this smoke test
  does not establish complete debugger compatibility.
* The full gate runs a ZFS-root amd64 guest, two vCPUs, QEMU TCG `-cpu max`,
  with INVARIANTS/WITNESS, three rounds of the new tests and prior suites.
  This broader run was stopped during the separate io_uring follow-ups after
  the user's instruction to leave that effort to its other owner. It is not a
  completed full-gate pass. The requested batch is qualified by the final-module
  focused run and native/client checks described below.

A final review corrected vfork event selection: a disabled TRACEVFORK must not
fall back to TRACEFORK. The `selective` case now exercises all nine combinations
of fork/vfork/process-clone against the three event options; the Linux oracle
passes. `linux64-selection.log` records the rebuild. `final-source-delta.json`
pins that one-condition implementation change and expanded tests. The full2
image predates this correction; affected suites are rerun separately on the
final module. `focus8.console.log` passes all 351 recorded executions (90
ptrace/register/native/access, 24 cookie, 42 XSAVE, 84 multicast, three native
multicast, 42 peer names, 60 process events, three peer capability groups and
three native exit groups), plus the eight-cycle exit-detach probe. It reports
a healthy ZFS pool, no panic/lock-order diagnostics and clean power-off.
`client2` repeats the GDB/Python client checks on this final module. Kernel and linux_common hashes are unchanged. Earlier full-gate
results must not be described as a full run of the corrected module.

Earlier attempts and corrections are preserved, including a redundant IPv6
loopback setup command that stopped `full1` before the new suite. `full2`
removes that command; no kernel change was needed. Supplemental `linux_ptrace_exit_lifecycle` executes eight detach-at-exit-stop
cycles successfully on Linux (`oracle13`) and the same BSD kernel/modules
(`supplement1`). It is separate from the frozen full-gate payload. An exploratory
SIGKILL-at-exit-stop variant timed out on the Linux reference VM (`oracle10`
through `oracle12`); that behavior is not qualified or silently counted as a
pass. The exploratory source is retained in the artifact directory.

References: Linux v6.18
[SO_PEERNAME](https://github.com/torvalds/linux/blob/v6.18/net/core/sock.c),
[IPv4 multicast](https://github.com/torvalds/linux/blob/v6.18/net/ipv4/igmp.c),
[IPv6 multicast](https://github.com/torvalds/linux/blob/v6.18/net/ipv6/mcast.c),
[ptrace](https://github.com/torvalds/linux/blob/v6.18/kernel/ptrace.c), and
[exit](https://github.com/torvalds/linux/blob/v6.18/kernel/exit.c).

`focus7` completed the same 351 assertions but its background shutdown helper
did not power the VM off after the init script returned. It was stopped and is
not counted as a clean VM run. `focus8` keeps the init script alive during the
shutdown handoff and provides a bounded halt fallback; shutdown completed before
the fallback. The minimal image lacks wall/getty, explaining those userland
messages; they are not kernel diagnostic failures. No kernel/module change was
made between those runs.
