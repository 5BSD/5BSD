# System Gates

A system gate is a kernel-held claim on one privileged operation: loading a
module, stepping the clock, creating a jail, writing a protected sysctl.
5BSD has gates because its base brokers are born in capability mode, and a
Capsicum sandbox cannot issue `settimeofday(2)` or `kldload(2)` at all,
whatever uid it runs as. Rather than loosen the sandbox, the plane moves the
privileged operation into the kernel and lets a held gate stand in for the
privilege check. This chapter explains that de-ambient framework: what a
gate is, how claims and tokens flow, how a manifest declares one, and which
daemons hold which gates.

The mechanism is the `system` service of the `mac_capability` framework,
documented in mac_capability_system(4) and implemented in
`sys/dev/mac_capability/mac_capability_system.c`. It is part of the
mandatory plane in every GENERIC kernel.

## Why the operation runs in the kernel

The first shape of a gate is a MACF hook. When a claim on `SYS_GATE_REBOOT`
exists, `mpo_system_check_reboot` denies every process except the claim
owner and its authorized token holders. Root is not exempt; the hook runs
after the kernel's own priv(9) check and adds nonce isolation on top. That
shape suits an ambient daemon that can still make the system call.

A born-in-capability-mode broker cannot make the system call. Capability
mode refuses `settimeofday(2)`, `adjtime(2)` and `jail_set(2)` at the
syscall boundary, and `kldload(2)` needs a path lookup the sandbox cannot
perform. The second shape of a gate therefore adds *perform* operations:
the broker sends a request over its capability descriptor, and the kernel
executes the primitive in kernel context on the broker's behalf. The held
gate is the sole authority; no priv(9) check runs behind it, and capability
mode is never loosened for the raw system call. The design note in the
source calls this CALL-does-op.

Because a perform operation has no privilege check behind it, its authority
test is stricter than the hook's. `sys_check_gate()` (the hook path) allows
an ambient caller when the gate is unclaimed, since the ambient syscall
still runs its own priv(9) check. `sys_holds_gate()` (the perform path)
succeeds only when the caller owns, or is authorized against, a claim
covering the gate; an unclaimed gate, an unlabeled caller and a labeled
caller without the claim are all denied with `EPERM`, root included.

## The gate list

Gates are bits in the `gates` field of `struct sys_request` and may be
combined. Bit `0x0004` once gated module enumeration; it is retired because
the DTrace toolchain needs read-only `kldstat(2)`, and a claim carrying it
is rejected with `EINVAL`.

| Gate | Value | MACF hooks | Perform operations |
|---|---|---|---|
| `SYS_GATE_KLDLOAD` | 0x0001 | `mpo_kld_check_load` | `SYS_OP_KLDLOAD` |
| `SYS_GATE_KLDUNLOAD` | 0x0002 | `mpo_kld_check_unload` | `SYS_OP_KLDUNLOAD` |
| `SYS_GATE_REBOOT` | 0x0008 | `mpo_system_check_reboot` | none |
| `SYS_GATE_SWAPON` | 0x0010 | `mpo_system_check_swapon` | none |
| `SYS_GATE_SWAPOFF` | 0x0020 | `mpo_system_check_swapoff` | none |
| `SYS_GATE_SYSCTL` | 0x0040 | `mpo_system_check_sysctl` (per OID when scoped) | `SYS_OP_SYSCTL` |
| `SYS_GATE_KENV` | 0x0080 | `mpo_kenv_check_set`, `_unset` | none |
| `SYS_GATE_ACCT` | 0x0100 | `mpo_system_check_acct` | none |
| `SYS_GATE_AUDIT` | 0x0200 | `mpo_system_check_auditon`, `_auditctl` | none |
| `SYS_GATE_KENV_READ` | 0x0400 | `mpo_kenv_check_get`, `_dump` | none |
| `SYS_GATE_SETTIME` | 0x0800 | none (perform-only) | `SYS_OP_SETTIME`, `SYS_OP_ADJTIME` |
| `SYS_GATE_JAIL` | 0x1000 | none (perform-only) | `SYS_OP_JAIL_SET`, `SYS_OP_JAIL_GET` |

`SYS_GATE_ALL` is `0x1ffb`. The two perform-only gates install no hook: the
ambient `settimeofday(2)` and `jail_set(2)` keep their ordinary privilege
checks and stay refused in capability mode, so holding `SETTIME` gives a
broker exactly one new ability, the perform operation, and takes nothing
from an ambient administrator.

## Claim, mint, authorize

The protocol has four state operations and seven perform operations, all
sent with `MAC_CAPABILITY_CALL` on an instance descriptor connected to the
service named `system`. The caller must carry a program nonce (see
[The MAC Capability Framework](mac-capability.md)); an unlabeled caller
gets `ENXIO`.

| Operation | Effect |
|---|---|
| `SYS_OP_CLAIM` (1) | the caller's nonce becomes owner of the named gates; gates accumulate on the instance; a `SYSCTL` claim may carry an OID payload |
| `SYS_OP_RELEASE` (2) | owner releases the claim, or subtracts listed OIDs from a scoped set |
| `SYS_OP_MINT` (3) | owner creates a token descriptor covering a subset of its gates; returned as the reply fd |
| `SYS_OP_AUTHORIZE` (4) | called on a token fd; adds the caller's nonce to the authorized set while the token stays open |
| `SYS_OP_SETTIME` (5), `SYS_OP_ADJTIME` (6) | step or slew `CLOCK_REALTIME` through `kern_settime_gated()` and `kern_adjtime_gated()` |
| `SYS_OP_SYSCTL` (7) | read and/or write one MIB through `kernel_sysctl()` with the `SCTL_GATED` flag |
| `SYS_OP_KLDLOAD` (8), `SYS_OP_KLDUNLOAD` (9) | load by name or unload by file id through `kern_kldload_gated()` and `kern_kldunload_gated()` |
| `SYS_OP_JAIL_SET` (10), `SYS_OP_JAIL_GET` (11) | create, update or query a jail through `kern_jail_set_gated()`; `JAIL_ATTACH` and descriptor-input forms are refused |

Delegation is by token narrowing. A claim owner mints a token covering only
some of its gates and hands the descriptor to another process, which
authorizes it; the recipient gains exactly those gates and nothing else.
Closing the token revokes every authorization it granted, closing the
claiming instance releases the gates, and
`kern.mac_capability_system.max_auth` bounds the total number of
outstanding authorizations (0 is unlimited; `SYS_OP_AUTHORIZE` fails with
`ENOSPC` at the limit).

In a running 5BSD system the claim owner is always capsule. `/dev/mac_capability`
is isolated to capsule's nonce at boot, so a provider cannot open the device
and cannot issue `SYS_OP_CLAIM` itself. What a provider receives is a
delivered token, and the delivery path is the manifest.

## Declaring a gate in the manifest

A unit that must perform a privileged kernel operation declares it in the
`capabilities` object of its `Unit.ucl`. This is the only `capabilities`
declaration that survives in the manifest format; every resource grant was
removed in favour of runtime self-service (see [Bundles and
Manifests](../plane/bundles-and-manifests.md)).

```
# BSDSysctl: hold the sysctl gate, become sole writer of one tunable
capabilities {
    system  = ["sysctl"];
    isolate = ["kern.maxfiles"];
}
```

`system` is an array of distinct names from `kldload`, `kldunload`,
`reboot`, `swapon`, `swapoff`, `sysctl`, `kenv`, `kenv_read`, `acct`,
`audit`, `settime` and `jail`, the same names capsule.conf(5) accepts in
`claims.system`. An unknown or duplicated name rejects the manifest.

At launch switchboard asks capsule to claim the gates and mint one token
carrying exactly the declared set, then delivers it as a bootstrap
capability of type `system`. The program calls
`service_provider_authorize_capabilities(3)` (or
`service_authorize_capabilities(3)` for a plain unit), which issues
`SYS_OP_AUTHORIZE` on the token and makes the unit's nonce an authorized
holder. From then on the unit performs the operation through the matching
`service_system_*` call in libservice(3):

| Call | Gate | Wraps |
|---|---|---|
| `service_system_settime(token, ts)` | `settime` | `SYS_OP_SETTIME` |
| `service_system_adjtime(token, delta, old)` | `settime` | `SYS_OP_ADJTIME` |
| `service_system_sysctl(token, mib, len, old, oldlen, new, newlen)` | `sysctl` | `SYS_OP_SYSCTL` |
| `service_system_kldload(token, name, &fileid)` | `kldload` | `SYS_OP_KLDLOAD` |
| `service_system_kldunload(token, fileid, flags)` | `kldunload` | `SYS_OP_KLDUNLOAD` |
| `service_system_jail_set(token, iov, niov, flags, &jid, &descfd)` | `jail` | `SYS_OP_JAIL_SET` |
| `service_system_jail_get(token, iov, niov, flags, &jid, &descfd)` | `jail` | `SYS_OP_JAIL_GET` |

`service_system_token_dup(3)` returns a caller-owned duplicate of the
delivered token so a privilege-separated provider can hand one scoped
operation to a per-client worker whose authority drop closes the tracked
token. The `capabilities` object is stripped from any unit loaded from a
per-user agent directory, and a unit that declares it counts one extra
bootstrap descriptor.

The declaration is the grant. libcapbundle parses the manifest through a
descriptor opened `O_VERIFY`, and switchboard opens the program `O_VERIFY`,
so when [mac_veriexec](veriexec.md) enforces, a unit's gate set is exactly
what its verified bundle declares. There is no allow-list of gate-holding
programs anywhere in switchboard; that was a deliberate removal.

## Per-OID sysctl isolation

`SYS_GATE_SYSCTL` is coarse by default: a claim without a payload isolates
every privileged sysctl write. That is too blunt for a broker that should
own two tunables and leave the rest of the namespace writable, so a
`SYS_OP_CLAIM` carrying `SYS_GATE_SYSCTL` may append a
`struct sys_sysctl_oidset` of 1 to `SYS_SYSCTL_MAXOIDS` (64) MIB entries,
each with a depth of 1 to `CTL_MAXNAME`. The kernel detects the payload by
request length and validates it fail-closed: a wrong length is `EINVAL`, a
set that would exceed 64 entries is `ENOSPC`, and no partial claim is
created.

A scoped claim isolates exactly the listed OIDs. Reads and name resolution
are never gated, `CTLFLAG_ANYBODY` nodes stay exempt, and every other
privileged write keeps its ordinary `PRIV_SYSCTL_WRITE` check. Repeated
claims union new OIDs into the set (and convert a coarse claim into a
scoped one); a release with a payload subtracts exactly those OIDs without
dropping the claim. The identity compared is the MIB, reconstructed by
walking `SYSCTL_PARENT` from the leaf, never an OID pointer, so dynamic
nodes carry no lifetime hazard.

switchboard delegates the sysctl gate only in this scoped form. A manifest
with `system = ["sysctl"]` and no `isolate` list, or `sysctl` mixed with
another gate, is refused at launch, because a coarse claim would force
every privileged write on the machine through one broker. The design and
its verification are in `docs/capability-sysctl-isolation.md`.

The perform side is separate from the isolate set: `SYS_OP_SYSCTL` accesses
the node with `SCTL_GATED`, which lifts the capability-mode node
confinement and `PRIV_SYSCTL_WRITE` while keeping securelevel and the MAC
hooks, and it may target any OID the holder's own per-label policy allows,
not only the isolated ones. `sys/kern/kern_sysctl.c` documents both
exceptions at the confinement check.

## The gated kernel entry points

Each perform operation calls a kernel primitive that exists because of the
gate. They are declared in `sys/sys/syscallsubr.h`:

| Entry point | File | What differs from the syscall path |
|---|---|---|
| `kern_settime_gated()`, `kern_adjtime_gated()` | `sys/kern/kern_time.c` | no `PRIV_SETTIMEOFDAY` or `PRIV_ADJTIME` check; the held gate is the authority |
| `kernel_sysctl(..., SCTL_GATED)` | `sys/kern/kern_sysctl.c` | skips capability-mode node confinement and `PRIV_SYSCTL_WRITE`; securelevel and MAC hooks still apply |
| `kern_kldload_gated()`, `kern_kldunload_gated()` | `sys/kern/kern_linker.c` | no `PRIV_KLD_LOAD` or `PRIV_KLD_UNLOAD`; the path lookup runs under a transient suspension of the caller's capability-mode credential flag so the module can be found; securelevel applies |
| `kern_jail_set_gated()` | `sys/kern/kern_jail.c` | no `PRIV_JAIL_SET`; at most 16 parameters and 4096 bytes; a `desc` parameter installs the jail descriptor in the caller's table |

The transient credential change in the kldload path is worth stating
plainly: the kernel duplicates the credential, clears the capability-mode
flag on the copy for the duration of the lookup, and discards it. The
calling process never leaves capability mode.

## Who holds which gates

| Daemon | Manifest | Gates | What it does with them |
|---|---|---|---|
| BSDExtension (`system.SystemExtension`) | `usr.sbin/BSDExtension/capbundle/bsdextension.ucl` | `kldload`, `kldunload` | loads modules named by clients through `service_ensure_extension(3)` against its own allow-list; reclaims modules of uninstalled bundles |
| BSDNamespace (`system.Namespace`) | `usr.sbin/BSDNamespace/capbundle/bsdnamespace.ucl` | `jail` | creates label-scoped jails for `service_enter_namespace(3)` callers; the caller attaches itself over the returned jail descriptor |
| BSDSysctl (`system.Sysctl`) | `usr.sbin/BSDSysctl/capbundle/bsdsysctl.ucl` | `sysctl`, `isolate = ["kern.maxfiles"]` | reads and writes on behalf of clients per `Config/sysctl.conf`; sole writer of the isolated OID |
| BSDTime (`system.Time`) | `usr.sbin/BSDTime/capbundle/BSDTime.ucl` | `settime` | `SET` and `ADJUST` for clients allowed by `Config/time.conf` |
| BSDPower (`system.Power`) | `usr.sbin/BSDPower/capbundle/BSDPower.ucl` | none | born in capability mode without a gate: `ACPIIO_REQSLPSTATE` on `/dev/acpi` is gated by device access, so authority rides on a descriptor narrowed with `cap_ioctls_limit(2)`; reboot and halt stay with capsule |
| capsule | `claims.system` in capsule.conf(5) | whatever the operator lists | the shipped `capsule-daemon.conf` claims nothing; reboot, halt and poweroff go through the `system.lifecycle` capability and capsulectl(8) |

BSDPower is in the list because it is the counterexample: the de-ambient
pattern does not always need a gate. When the privilege is a device node
rather than a priv(9) check, a delivered `/dev` directory descriptor and a
rights-narrowed `openat(2)` are enough. BSDVM is the one base provider still
launched `ambient = true`; it is the next candidate for this framework.

## Observing and testing

Three DTrace probes under the `mac_capability_system` provider fire on
every decision: `deny(gate, owner, accessor)`, `allow(gate, owner,
accessor)` and `state(operation, owner, accessor, gates, pid, error)`, where
`operation` names claims, releases, mints, authorizations and each perform
op with its `-deny` variant.

```
# dtrace -n 'mac_capability_system::deny {
    printf("%s owner=%u accessor=%u", copyinstr(arg0), arg1, arg2); }'
```

`tests/sys/mac_capability/mac_capability_system_test.c` carries 38 ATF
cases covering claim ownership, token narrowing, per-OID scoping, the
perform operations and the strict holder test; they run on a plane-free
boot through `tests/sys/mac_capability/run_tests.sh`. Each gate daemon has
its own provider tests, and the sysctl isolation was verified end to end on
a production plane: a foreign direct write to `kern.maxfiles` is denied,
the same write through sysctlcmpctl(8) succeeds.

## Limits

A gate is per operation class, not per object. `KLDLOAD` covers every
module; which modules a client may request is BSDExtension's allow-list,
not the kernel's. `JAIL` covers jail creation; label scoping of jail names
is BSDNamespace's rule. The kernel enforces who may perform, the broker
enforces what. The reboot, swap, kenv, accounting and audit gates have hooks
but no perform operations, so a born-in-capability-mode holder cannot yet
use them; they serve ambient claimants. The framework is designed to grow
by adding perform operations for those gates as their brokers move into
capability mode.
