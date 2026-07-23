# VirtIO-vsock adversarial review loop

Use this prompt against the complete change range and current worktree.  Do
not treat a successful build, a happy-path VM run, or a previous review as
proof that a path is correct.

## Scope

Review these implementations as separate backends sharing one guest-facing
VirtIO device:

* bhyve `backend=userspace`: `usr.sbin/bhyve/pci_virtio_vsock.c`, its Unix
  control socket, relay sockets, virtqueues, reset, and teardown;
* bhyve `backend=kernel`: the same PCI device's `/dev/vsock` packet bridge;
* the kernel provider: `sys/kern/uipc_vsock_user.c` and the transport/domain
  code it calls in `sys/kern/uipc_vsock.c`;
* all direct harnesses and live tests under `tests/sys/kern/vsock_*`.

Review the diff and the surrounding implementation.  Code outside the diff
is in scope when a changed call site depends on its lifetime, locking, error,
or protocol contract.

## Rules for every pass

1. State the invariants before judging the code.  Include ownership, lock
   state, connection state, queue bounds, descriptor ownership, credit
   accounting, record boundaries, and who must wake whom.
2. Trace every return value and errno from its origin through cleanup and
   recovery.  An error that is logged and then leaves a dead queue, lost
   wakeup, leaked fd, consumed descriptor, or permanently failed backend is a
   finding.
3. Construct a concrete schedule or packet sequence that reaches the issue.
   Do not report a hypothetical race without identifying both racing
   operations and the missing serialization.
4. Check the existing tests before calling something uncovered.  A mock test
   only counts when it models the relevant ownership and failure semantics.
5. For each confirmed issue or gap, specify a regression test that fails
   before the fix and passes afterward.  Prefer deterministic fault injection
   over timing sleeps.
6. Re-read the final patch, not the remembered patch.  Check cleanup paths
   introduced by the test scaffolding too.
7. Report findings by severity with file/function, reachability, consequence,
   and evidence.  Separate confirmed defects, coverage gaps, and deliberate
   design tradeoffs.

## Passes in one cycle

Run every pass, even if an earlier pass found issues.

### Pass A: state, ownership, and lifetime

Follow attach, feature negotiation, connect, accept, data transfer,
half-close, disconnect, reset, detach, and initialization failure.  Look for
UAF, double close/free, stale callbacks, fd reuse, abandoned cdevpriv state,
packets surviving reset, and state transitions that cannot recover.

### Pass B: error propagation and recovery

At every allocation, read, write, writev, recvmsg, sendmsg, ioctl, poll,
mevent, virtqueue, and copy boundary, consider:

* `EAGAIN`, `EINTR`, hard error, EOF, zero progress, short I/O, malformed
  framing, allocation failure, and queue full;
* whether input was consumed before failure;
* whether retry preserves byte/record order and descriptor ownership;
* whether `NEEDS_RESET`, poll/kqueue readiness, logging, and DTrace reflect
  the resulting state;
* whether a successful reset demonstrably restores service.

### Pass C: concurrency and reset schedules

Interleave reset/detach with blocked provider read/write, a parked kernel
packet, a partially injected guest record, a pending control connection,
credit wait, TX backlog drain, kqueue detach, and callback dispatch.  Verify
lock order and all wakeups.  Require deterministic harness schedules for
important races.

### Pass D: hostile protocol and boundary values

Exercise wrong CIDs, wrong port pairs, reserved CIDs/ports, unknown operation
and type, invalid flags, control packets with payload, mismatched length,
zero-length records, maximum and maximum-plus-one payloads, wraparound credit,
excess descriptors, mixed descriptor directions, duplicate/colliding
requests, and stale packets after reset.  Compare STREAM and SEQPACKET
independently and check modern and legacy PCI transport.

### Pass E: resource exhaustion and longevity

Try connection, control-connection, provider-control, provider-data,
reassembly, TX-backlog, descriptor, and host socket limits.  Repeatedly fail
connections in both directions, then prove immediate recovery.  A soak must
reuse one bhyve process, include errors and abrupt teardown—not just
successful echo—and check fd, RSS, connection, and bounded-queue state after
warmup.

### Pass F: observability and security boundary

For every fatal error, nonfatal drop, reset, attach/detach, backpressure
episode, and resource-limit rejection, verify an operator can distinguish it
without packet payloads.  Check debug log volume, DTrace probe arguments and
lifetime safety, standard audit claims, Capsicum rights, privilege checks,
MAC hooks, and absence of ambient path/fd authority.

### Pass G: test validity

Deliberately break one load-bearing behavior in each harness category and
confirm the intended test fails.  Look for duplicate registrations, tests
that accept multiple unrelated errnos, mocks that cannot produce partial I/O,
fixed sleeps instead of readiness, leaked background processes, stale files,
and success checks that ignore one endpoint.

## Loop and termination

After fixing confirmed issues and adding tests, begin a new cycle with a
different pass order.  On the next cycle, start at the pass following the one
that found the last issue.  Continue until:

* one complete seven-pass cycle finds no new actionable defect or material
  coverage gap;
* sanitizer-backed direct harnesses and Werror builds pass;
* privileged provider tests pass on the installed kernel;
* modern userspace and kernel live matrices pass; and
* the same-process error-inclusive soak passes for both backends.

Do not claim absence of long-run bugs.  Record the duration, iterations,
traffic/error mix, diagnostic-kernel options, and final resource deltas so the
strength and limits of the evidence are explicit.
