# Capability Transfer (cap_xfer)

Descriptors are 5BSD's unit of authority, and stock FreeBSD lets any
descriptor travel without limit: `SCM_RIGHTS` to any process, inherited
by every fork, surviving every exec. For a capability system that is a
hole — a supervisor cannot hand a worker a credential and be sure it
stays there. `cap_xfer` closes it with per-descriptor, monotonically
tightening **transfer, exec, and fork limits**, plus ceilings on the
authority a permitted transfer conveys. Design document:
`/usr/src/DESIGN_CAP_XFER.md`.

## Transfer states

A `uint8_t fde_xfer_state` on `struct filedescent` — deliberately
orthogonal to `cap_rights_t`, so no `cap_rights_*` API can see or
change it. States (declared in `/usr/src/sys/sys/capsicum.h`):

| State | Semantics on send |
|---|---|
| `CAP_XFER_UNLIMITED` (0) | default; sender and receiver stay unlimited |
| `CAP_XFER_ONCE` (1) | one send; sender **and** receiver become `NONE` |
| `CAP_XFER_NONE` (2) | send fails with `ENOTCAPABLE` |

Transfer is per-hop, not a multi-hop budget: an `ONCE` send is a single
hop that exhausts the sender's entry and installs the receiver's endpoint
as `NONE`, so the receiver cannot forward it again. serviced uses `ONCE`
to give a consumer an endpoint it may use but not re-send; longer chains
are built by re-attenuating each hop explicitly. State
is inherited by `dup`/`dup2`/`dup3` (via `fde_copy()`) and by fork's
bulk table copy. `cap_xfer_limit(2)` follows a monotonic partial order:
`UNLIMITED` may narrow to `ONCE` or `NONE`, and `ONCE` may narrow to
`NONE`. Widening fails with `ENOTCAPABLE`.

## Post-transfer authority ceilings

Independently of *whether* an fd may move, `struct filedescent` carries
`fde_xfer_caps` ("maximum rights after transfer"). On a permitted
`SCM_RIGHTS` send, `unp_internalize()` intersects the descriptor's
current Capsicum caps with these ceilings, so the receiver gets
attenuated authority while the sender keeps its own:

```c
int cap_xfer_rights_limit(int fd, const cap_rights_t *rightsp);
int cap_xfer_ioctls_limit(int fd, const cap_ioctl_t *cmds, size_t ncmds);
int cap_xfer_fcntls_limit(int fd, uint32_t fcntlrights);
```

Dropping `CAP_IOCTL`/`CAP_FCNTL` from the ceiling clears the respective
sub-allowlists. All three are monotonic (`CAPFAIL_INCREASE` on any
attempt to widen).

## Exec and fork interactions

Classic `FD_CLOEXEC`/`FD_CLOFORK` flags are process-settable, so a
compromised program can simply clear them. `cap_xfer` adds locked
counterparts:

| State | Meaning |
|---|---|
| `CAP_CLOEXEC_UNLOCKED` / `CAP_CLOFORK_UNLOCKED` | default; flag freely settable |
| `CAP_CLOEXEC_LOCKED` / `CAP_CLOFORK_LOCKED` | close-on-exec/-fork forced, cannot be cleared |
| `CAP_CLOEXEC_ONCE` | survive exactly one exec, then transition to LOCKED |
| `CAP_CLOFORK_ONCE` | inherit into exactly one child, then LOCK **both** the parent and child entries |

Set via `cap_cloexec_limit(2)` and `cap_clofork_limit(2)`; monotonic
like everything else here. This is how serviced injects bootstrap
channels that survive its one supervised exec and nothing after it.

## Exported symbols

- Syscalls 603–608 (`STD|CAPENABLED` in
  `/usr/src/sys/kern/syscalls.master`): `cap_xfer_limit`,
  `cap_cloexec_limit`, `cap_clofork_limit`, `cap_xfer_rights_limit`,
  `cap_xfer_ioctls_limit`, `cap_xfer_fcntls_limit`; exported from libsys
  (`/usr/src/lib/libsys/Symbol.sys.map`) with man page
  `cap_xfer_limit.2`.
- Kernel: `kern_cap_xfer_limit()`, `kern_cap_xfer_rights_limit()`,
  `kern_cap_xfer_ioctls_limit()`, `kern_cap_xfer_fcntls_limit()`,
  `kern_cap_cloexec_limit()`, `kern_cap_clofork_limit()` in
  `/usr/src/sys/kern/sys_capability.c` (with `!CAPABILITIES` stubs).
- Enforcement points: `unp_internalize()` / `unp_externalize()` in
  `/usr/src/sys/kern/uipc_usrreq.c` (validate, consume under
  `FILEDESC_XLOCK`, propagate to the installed fd), and the
  mac_capability message path (`mac_capability_dev.c` SENDMSG/RECVMSG),
  which honors the same states for fds attached to capability messages.
- Observability: `fd:::xfer-consume` SDT probes fire on each budget
  consumption.

## Security invariants

- **Opt-in and invisible until used.** `CAP_XFER_UNLIMITED = 0` matches
  zeroed allocation in `_finstall()`/`fdfree()`; no existing code calls
  the new syscalls, so legacy software behaves identically.
- **Monotonic everywhere.** Transfer states, exec/fork locks, and
  ceilings only tighten; there is no clear/reset operation.
- **Orthogonal to Capsicum rights.** `cap_rights_limit()`,
  `cap_rights_clear()`, and `CAP_ALL` neither observe nor modify xfer
  state (verified by the `xfer_orthogonal_to_rights` test).
- **No TOCTOU on consume.** The ONCE consume is a write, so
  `unp_internalize()` was upgraded to `FILEDESC_XLOCK`; receive installs
  the fd and writes its state under a single `XLOCK`. No new locks were
  introduced.
- **Every descriptor-creating path audited.** `dup`, fork's `fdcopy()`,
  `dupfdopen()`, `fdgrowtable()`, `accept()`, `pipe()`, `socketpair()`,
  kqueue, eventfd, and `pdfork()` all yield UNLIMITED descriptors via
  `_finstall()`; the design doc records the audit.
- Kernel-created reply fds (e.g. `MAC_CAPABILITY_CALL` replies) start
  UNLIMITED by construction.
- Descriptor constructors can install a narrower initial state directly.
  EnvFD uses this to mint `ONCE` authority without a transient unlimited
  window; its regression suite verifies creator → consumer transfer and
  exhaustion at every endpoint.

## Tests

`/usr/src/tests/sys/kern/cap_xfer_test.c` (20 ATF cases: defaults,
widen-fails, dup inheritance, exhaustion over `SCM_RIGHTS`,
rights-orthogonality) and
`/usr/src/tests/sys/kern/cap_confinement_test.c` (cloexec/clofork ONCE
and LOCKED behavior, flag-override protection, full confinement
end-to-end). mac_capability propagation is covered in
`/usr/src/tests/sys/mac_capability/mac_capability_test.c`.
The descriptor-wide disposable-VM harness in
`/usr/src/tools/test/capability-qemu/` also exercises `ONCE` in the real
kernel together with EnvFD, Crypto, BSDNotify, filesystem flavors, and
TrustedZFS.
