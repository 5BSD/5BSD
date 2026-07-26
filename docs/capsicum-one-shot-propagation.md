# Capsicum one-shot descriptor propagation

## Status

The implementation is committed in:

```text
54353bbad1f capsicum: add one-shot exec and fork propagation
```

This document records the API and lifecycle semantics needed to rebuild,
reboot, and validate the change.

## Purpose

The existing propagation locks can prevent a descriptor from crossing an
`execve(2)` or `fork(2)` boundary:

```c
cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED);
cap_clofork_limit(fd, CAP_CLOFORK_LOCKED);
```

The one-shot states add an intermediate restriction for supervisor/child
launch patterns:

```c
cap_cloexec_limit(fd, CAP_CLOEXEC_ONCE);
cap_clofork_limit(fd, CAP_CLOFORK_ONCE);
```

They allow the descriptor to cross one applicable boundary and then
irreversibly change the surviving descriptor entries to the corresponding
locked state.

These are propagation states on a descriptor entry. They are separate from
Capsicum operation rights and from the discretionary `FD_CLOEXEC` and
`FD_CLOFORK` flags.

## Public API

The existing system calls accept the new states declared in
`sys/sys/capsicum.h`:

```c
#define CAP_CLOEXEC_UNLOCKED  0
#define CAP_CLOEXEC_LOCKED    1
#define CAP_CLOEXEC_ONCE      2

#define CAP_CLOFORK_UNLOCKED  0
#define CAP_CLOFORK_LOCKED    1
#define CAP_CLOFORK_ONCE      2

int cap_cloexec_limit(int fd, int state);
int cap_clofork_limit(int fd, int state);
```

The numeric values are retained for ABI compatibility and are not in
semantic order. The kernel explicitly ranks them as:

```text
UNLOCKED -> ONCE -> LOCKED
UNLOCKED ---------> LOCKED
```

Calling either limit operation with the current state is allowed. Tightening
from `ONCE` directly to `LOCKED` is allowed. Any attempt to move toward
`UNLOCKED`, or from `LOCKED` back to `ONCE`, fails with `ENOTCAPABLE`.
Invalid state values fail with `EINVAL`.

Both calls remain capability-mode enabled.

## Exec-once semantics

`CAP_CLOEXEC_ONCE` means:

1. The descriptor may survive one successful exec boundary.
2. If it survives, the descriptor entry in the new image becomes
   `CAP_CLOEXEC_LOCKED`.
3. The following exec closes it.

The exec close decision is effectively:

```text
close = descriptor is a message queue
     OR FD_CLOEXEC is set
     OR state is CAP_CLOEXEC_LOCKED
     OR a MAC inheritance check denies it
```

If none of those closes the descriptor and its state is
`CAP_CLOEXEC_ONCE`, `fdcloseexec()` changes the state to
`CAP_CLOEXEC_LOCKED`.

`CAP_CLOEXEC_ONCE` does not override another close reason. In particular,
setting `FD_CLOEXEC` still closes the descriptor at the first exec. There is
then no surviving entry whose state needs to be consumed.

Lifecycle:

```text
before first exec       open, CAP_CLOEXEC_ONCE
after first exec        open, CAP_CLOEXEC_LOCKED
after second exec       closed
```

## Fork-once semantics

`CAP_CLOFORK_ONCE` means:

1. One child may inherit the descriptor.
2. When that inheritance occurs, the parent entry becomes
   `CAP_CLOFORK_LOCKED`.
3. The newly installed child entry is also
   `CAP_CLOFORK_LOCKED`.
4. Neither branch can propagate that entry through another fork.

Lifecycle:

```text
parent before fork      open, CAP_CLOFORK_ONCE

first child             open, CAP_CLOFORK_LOCKED
parent after fork       open, CAP_CLOFORK_LOCKED

later child             descriptor omitted
first child's child     descriptor omitted
```

`CAP_CLOFORK_ONCE` does not override `FD_CLOFORK` or a file-type restriction.
If the descriptor is omitted from a child for another reason, no inheritance
occurred and the parent's one-shot state is not consumed.

Fork consumption takes the file-descriptor table's exclusive lock. Two
concurrent forks therefore cannot both consume the same one-shot descriptor
entry: exactly one child can inherit it.

Internal descriptor-table copies, such as unsharing a table, do not consume a
fork boundary. `fdcopy()` now receives an `isfork` argument to distinguish a
real child-table construction from an internal copy.

## Interaction with ordinary descriptor operations

### `FD_CLOEXEC` and `FD_CLOFORK`

The traditional flags remain independently settable and clearable with
`F_SETFD`. Changing them does not change or weaken the monotonic propagation
state. At an exec or fork boundary, either the discretionary flag or the
locked state is sufficient to prevent propagation.

As before, `FD_CLOFORK` is cleared from descriptors that survive an exec.

### `dup(2)`

A duplicate receives a copy of both propagation states. The state belongs to
each descriptor entry, not to the shared underlying `struct file`.

Consequently, duplicating an `ONCE` descriptor creates another descriptor
entry with its own copied state. These APIs constrain each entry; they do not
provide a global one-shot counter covering every alias of an underlying file.

### `SCM_RIGHTS` and mac_capability channels

Descriptor transfer preserves the exec and fork propagation states exactly.
The receiver cannot widen an `ONCE` state back to `UNLOCKED`.

Transfer permission is a separate axis:

```c
cap_xfer_limit(fd, CAP_XFER_NONE);
```

Use `CAP_XFER_NONE` when the holder must not send the descriptor through
`SCM_RIGHTS` or a mac_capability channel. One-shot exec/fork states alone do
not prohibit descriptor transfer.

### Closing and reopening

Closing the descriptor destroys its entry. A subsequently opened descriptor
starts with the default `UNLOCKED` states, even if it reuses the same integer
descriptor number.

## Intended supervisor pattern

A supervisor can prepare a resource for one child that will fork and exec:

```c
if (cap_xfer_limit(fd, CAP_XFER_NONE) == -1)
        err(1, "cap_xfer_limit");
if (cap_clofork_limit(fd, CAP_CLOFORK_ONCE) == -1)
        err(1, "cap_clofork_limit");
if (cap_cloexec_limit(fd, CAP_CLOEXEC_ONCE) == -1)
        err(1, "cap_cloexec_limit");

pid = fork();
if (pid == 0)
        execl(path, path, NULL);
```

After the fork:

- the selected child has the descriptor, but cannot pass it to a grandchild;
- the parent retains its entry, but cannot give it to a later child;
- the child may carry it through its first exec;
- the new image cannot carry it through a second exec; and
- neither entry can be transferred when `CAP_XFER_NONE` is also set.

The holder can still use or duplicate the descriptor according to its
ordinary descriptor and Capsicum rights. These propagation controls are not
operation rights and do not prevent copying data obtained through the
descriptor.

## Kernel implementation

The principal implementation points are:

- `sys/sys/capsicum.h`
  defines the two new public states.
- `sys/kern/sys_capability.c`
  validates semantic restriction ranks and preserves monotonicity.
- `sys/sys/filedesc.h`
  stores the states in `struct filedescent`; `fde_copy()` copies them.
- `sys/kern/kern_descrip.c:fdcloseexec()`
  consumes `CAP_CLOEXEC_ONCE` after all close checks allow the descriptor to
  survive.
- `sys/kern/kern_descrip.c:fdcopy()`
  consumes `CAP_CLOFORK_ONCE` only while constructing a real child's
  descriptor table and locks the parent and child entries atomically.
- `sys/kern/kern_fork.c`
  identifies the `fdcopy()` operation as a real fork.
- `sys/kern/uipc_usrreq.c`
  preserves the states through Unix-domain `SCM_RIGHTS`.
- `sys/dev/mac_capability/mac_capability_dev.c`
  preserves the states through mac_capability descriptor passing.

No new descriptor type is introduced.

## DTrace observability

`share/dtrace/capsicum-changes` reports both requested limits and automatic
one-shot consumption.

Limit probes:

```text
capsicum:::cloexec-limit
capsicum:::clofork-limit
```

Consumption probes:

```text
fd:::cloexec-consume
fd:::clofork-consume
```

The exec probe reports the descriptor, process, file type, credentials, and
new locked state. The fork probe reports the descriptor, parent, child, file
type, and credentials.

Run the existing script as root while exercising the tests:

```sh
/usr/src/share/dtrace/capsicum-changes
```

## Test coverage

The main ATF program is:

```text
tests/sys/kern/cap_confinement_test.c
```

It verifies:

- the default states;
- idempotent limit calls;
- monotonic `UNLOCKED -> ONCE -> LOCKED` transitions;
- rejection of widening with `ENOTCAPABLE`;
- invalid descriptors and invalid state values;
- `CAP_CLOEXEC_ONCE` surviving one exec and closing on the second;
- `FD_CLOEXEC` taking precedence without consuming a surviving entry;
- `CAP_CLOFORK_ONCE` reaching one child and locking both branches;
- `FD_CLOFORK` taking precedence without consuming the parent's allowance;
- exactly one winner across two concurrent forks;
- preservation through `dup(2)`;
- preservation and end-to-end enforcement after `SCM_RIGHTS`; and
- operation from Capsicum capability mode.

`tests/sys/mac_capability/mac_capability_test.c` additionally verifies that
mac_capability `SENDMSG`/`RECVMSG` and call/reply paths preserve the
intermediate states, reject widening, and enforce fork-once after receipt.

## Reboot and validation checklist

1. Confirm the source commit:

   ```sh
   cd /usr/src
   git log -1 --oneline
   ```

2. Build and install the kernel using the desired kernel configuration:

   ```sh
   cd /usr/src
   make buildkernel KERNCONF=GENERIC
   doas make installkernel KERNCONF=GENERIC
   ```

3. Reboot into the new kernel.

4. Rebuild/install the matching userland and tests as required by the local
   development workflow. The public constants are in `sys/capsicum.h`, so
   the tests must be compiled against the updated headers.

5. Run the kernel confinement test:

   ```sh
   kyua test -k /usr/tests/Kyuafile sys/kern/cap_confinement_test
   kyua report
   ```

6. Load the mac_capability test dependencies and run the mac_capability test
   suite according to `tests/sys/mac_capability/run_tests.sh`.

7. Optionally run `share/dtrace/capsicum-changes` in another terminal and
   confirm that the expected `CLOEXEC-ONCE` and `CLOFORK-ONCE` consumption
   events appear.

## Manual expected results

For an `FD_CLOEXEC`-clear descriptor limited to `CAP_CLOEXEC_ONCE`:

```text
exec #1: descriptor open
exec #2: EBADF
```

For an `FD_CLOFORK`-clear descriptor limited to `CAP_CLOFORK_ONCE`:

```text
child #1: descriptor open
child #1's child: EBADF
parent's child #2: EBADF
parent itself: descriptor still open
```

Those two sequences are the core observable contract.
