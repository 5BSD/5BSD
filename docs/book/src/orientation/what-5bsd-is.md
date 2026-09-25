# What 5BSD Is

5BSD is a derivative of FreeBSD 16-CURRENT that adds a capability plane beside
the classic system. The classic system is FreeBSD, kept whole so that nothing
an operator or a program relies on stops working. The plane is a second way of
running software on the same kernel, in which a program's authority is the set
of unforgeable descriptors it holds rather than the uid it runs as. 5BSD
exists because Capsicum confines a process but gives it no capability-shaped
way to obtain or delegate authority; the plane supplies that, and the
principles below follow from taking it seriously.

## What stays FreeBSD

5BSD is not a rewrite, not a microkernel, and not a new userland. It is
derived from FreeBSD `main` at the commit `bc301fee4cb` that is the merge base
of the 5BSD `dev` branch, and it tracks FreeBSD's kernel, libc, toolchain,
ZFS, jails, rc(8), ports and pkg(8). The FreeBSD Handbook describes 5BSD
correctly wherever this book does not say otherwise, and the FreeBSD man pages
remain the 5BSD man pages, with 104 pages added and a smaller number revised.

Two structural decisions narrow the baseline. 5BSD is 64-bit only: `LIB32` is
a broken option in `share/mk/src.opts.mk`, GENERIC carries `nooptions
COMPAT_FREEBSD32`, and `sys/sys/zfshandle.h` refuses to compile on any
non-64-bit kernel or user ABI, so the storage plane cannot exist in a 32-bit
world. And a ZFS pool is required for a fully working installation: the
storage plane provisions `/Capabilities/Data` as datasets under the root pool,
so the loader defaults load `zfs.ko` on every boot.

The Linux ABI is a first-class execution target rather than an afterthought.
`stand/defaults/loader.conf` loads `linux_common` and `linux64`,
`libexec/rc/rc.conf` sets `linux_enable="YES"`, and the emulator covers the
64-bit Linux system call table so that unmodified Linux binaries run with the
5BSD security stack enforcing beneath the translation boundary. Linux
seccomp and Landlock emulation is in progress and not yet committed.

## What 5BSD adds

The divergence inventory in `docs/5bsd-inventory.md` measures the fork at
1304 commits since the baseline, 8997 added files, 992 modified upstream
files, 26 new native system calls and 61 new MAC policy hooks. The additions
fall into the areas below; each has a part of this book.

| Area | Where it lives | Part of this book |
|---|---|---|
| Kernel capability core (mac_capability, Capsicum and procdesc extensions) | `sys/dev/mac_capability`, `sys/kern` | II |
| Security modules (mac_abac, OES, MAC framework changes) | `sys/security` | II |
| Plane runtime (capsule, switchboard, libservice, libcapbundle) | `usr.sbin/capsule`, `usr.sbin/switchboard`, `lib/libservice` | III |
| Sixteen system capability providers and their client libraries | `usr.sbin/BSD*`, `lib/lib*cmp` | IV |
| Storage: TrustedZFS and BSDFilesystem | `sys/contrib/openzfs`, `usr.sbin/BSDFilesystem` | III, IV |
| Linux emulation and the squeue completion-ring engine | `sys/compat/linux`, `sys/kern/sys_squeue.c` | V |
| Virtualization (bhyve(8) engine, VirtIO guest stack, vsock, BSDVM) | `usr.sbin/bhyve`, `sys/dev/virtio`, `usr.sbin/BSDVM` | IV, V |
| Bluetooth host, BLE mesh and virtual HCI | `usr.sbin/bluetooth/BSDBluetooth` | IV |
| Observability (bsdinstruments, hwtlm, bsdtrace, libotelexport, 87 DTrace scripts) | `usr.sbin`, `share/dtrace` | VII |
| Build, pkgbase packaging, installer and boot | `packages/`, `release/`, `stand/` | VII |
| Tests (the largest single addition, 6353 files) | `tests/`, `usr.sbin/*/tests` | VI |

## The capability plane in one page

The plane has four kinds of process, and one rule that binds them.

**Capsule** is PID 1. It is a port of init(8)'s state machine with one added
state: before multi-user, it opens `/dev/mac_capability`, claims the device
exclusively, claims the system gates it is configured to hold, shields itself
with capprotect, and starts one child through pdfork(2). It is the smallest
possible root of trust and the one place authority is created. See
[Capsule, PID 1](../plane/capsule.md).

**Switchboard** is that child, the 5BSD service manager. It scans capability
bundles under `/Capabilities/System`, `/Capabilities/Apps` and
`/Capabilities/Users/<uid>/Agents`, launches their units, supervises them by
process descriptor, and runs the naming registry through which every service
is found and started on demand. It holds no authority of its own to give away;
it launches and it switches. See [Switchboard](../plane/switchboard.md).

**Providers** are switchboard-launched daemons that each broker one facility
under one well-known wire name. `system.Filesystem` brokers storage,
`system.Network` brokers sockets, `system.Device` brokers `/dev` leaves, and
so on through the sixteen listed below. A provider holds a capability to its
facility and hands back Capsicum-narrowed descriptors to callers, scoped by
the caller's label.

**Consumers** are everything else on the plane: applications and agents that
reach providers by name over a per-process lookup channel and receive
narrowed descriptors in return. A consumer never opens a global path, never
binds a port by itself and never inspects a peer uid.

The rule that binds them: **a service performs an operation if and only if the
channel the request arrived on carries a capability whose rights permit it.**
It never consults the caller's uid, gid, path, PID or a signal. The kernel
stamps every message with a credential trailer that includes the sender's
program nonce, a random 64-bit MAC label inherited across fork and rotated on
exec, so the identity a provider sees is the program, not the user. The
mechanism is in [The MAC Capability Framework](../capability/mac-capability.md)
and the rule in [The Authority Model](../capability/authority-model.md).

## The driving principles

**Authority is a held capability, not a uid, a path or a PID.** Every
authorization decision on the plane is made by inspecting the endpoint a
request arrived on. Where uid still decides something (a provider running as
root to reach a pool handle, an rc daemon on the BSD side) the book calls it
transitional and says so. The one legitimate identity-to-capability
translation is BSDAuth, the mint boundary: login, su and sshd authenticate a
credential and then ask `system.Auth` what the session may hold, decided by
`/Capabilities/Config/principal-policy.ucl`. Denial and non-existence look the
same to a caller, which is the intended information posture.

**Born in capability mode.** A daemon must not have a window in which it runs
unsandboxed. Switchboard calls cap_enter(2) in the child and then fexecve(2)s
the verified bundle program, so from its first instruction the daemon can use
only the descriptors switchboard delivered: its bootstrap object at fd 5, its
service channel at fd 3, the directories its manifest named. Fifteen of the
sixteen providers launch this way; BSDVM is the one documented `ambient =
true` exception. Privileged kernel work that a sandboxed daemon cannot do by
itself (setting the clock, loading a module, creating a jail, writing a
sysctl) runs through a system gate token minted by capsule. See
[Capability Mode and the Born-Sandboxed Launch](../capability/capability-mode-and-launch.md)
and [System Gates](../capability/system-gates.md).

**Fail soft; no hard dependencies.** Units carry no startup ordering and no
dependency graph. A consumer acquires a capability lazily when it first needs
it, through `service_open(3)`, and if the provider is down the call fails and
the consumer retries later rather than exiting. Switchboard launches every
boot unit in parallel and in parallel with `/etc/rc`; a lookup for a unit that
is not running starts it, and concurrent lookups coalesce onto one launch.
The whole login-channel carry is best-effort by design: if minting fails, the
session runs exactly as it would on FreeBSD, with no channel.

**The per-app home: one app, one directory, one delete.** Each unit's
persistent state lives in one container under `/Capabilities/Data/<bundle>/
<unit>/`, provisioned by BSDFilesystem as a dataset the unit reaches only
through a delivered handle. Providers that persist bytes on a unit's behalf
store them there. When a bundle is removed, every provider runs a reconcile
(libcapreclaim, shown by reclaimstat(8)) that reaps state whose owner is gone.
See [Containers and Storage](../plane/containers-and-storage.md).

**Everything traced.** Every plane program carries a USDT DTrace provider,
the kernel gains roughly 65 SDT providers, and 87 ready-made scripts ship in
`/usr/share/dtrace`. Tracing is itself a capability: BSDTrace delivers a
rights-limited `/dev/dtrace` descriptor to callers that hold the
`system.trace.client` anointment. Structured logs go through `system.Log`,
security events through `system.Audit`, which commits BSM records from inside
capability mode. See [Logging, Audit and Trace](../plane/logging-audit-trace.md).

**Declaration is the grant, and verified execution is assumed.** A unit's
manifest is its policy. `ambient`, `mint_authority`, `capabilities { system }`
and `level` are honoured only for a bundle under `/Capabilities/System`, and
switchboard rejects a bundle that is not root-owned or that contains symlinks
or undeclared units. The design assumes mac_veriexec will enforce that only
signed programs run from those bundles; there is no hardcoded allow-list in
code as a fallback. Today MAC_VERIEXEC is compiled into GENERIC, veriexec(8)
is hardened, but no signed base manifest is generated and enforcement is not
entered. See [Verified Execution](../capability/veriexec.md).

## The sixteen system capabilities

Each provider is a daemon under `usr.sbin/BSD*` with a BSD\*.8 man page, a
typed client library, a per-label policy file where the facility is
dangerous, and ATF tests. Thirteen launch at boot; BSDNamespace, BSDVM and
BSDBluetooth start on the first lookup. Ten run as the unprivileged
`capability` user (uid 976); BSDAudit, BSDAuth, BSDCrypto, BSDFilesystem,
BSDTrace and BSDVM run as root. Part IV has a chapter on each.

| Wire name | Provider | Purpose |
|---|---|---|
| `system.Audit` | BSDAudit | Submits BSM audit records on behalf of capability-mode units, with per-identity event policy and rate limiting |
| `system.Auth` | BSDAuth | The mint boundary: mints session lookup channels for login, su and sshd from the principal policy; serves anoint(1) elevation |
| `system.Crypto` | BSDCrypto | Factory for crypto descriptors: sessions, keys, digests, randomness, named keys with lease and rotation |
| `system.Device` | BSDDevice | Opens `/dev` leaves under a delivered directory and returns rights-narrowed, ioctl-whitelisted descriptors, default-deny per label |
| `system.SystemExtension` | BSDExtension | Loads and unloads kernel modules through the kldload gate from an allow-list; reclaims modules of removed bundles |
| `system.Filesystem` | BSDFilesystem | The storage broker over TrustedZFS: the `/Capabilities` layout, per-bundle containers, quota, snapshots, versions, transactions, isolated opens |
| `system.Log` | BSDLog | Structured log ingestion, segment storage, retention and query; seals the logs of removed bundles |
| `system.Namespace` | BSDNamespace | Creates and destroys label-scoped jails on request through the jail gate |
| `system.Network` | BSDNetwork | Delivers connected, listening and UDP sockets and name resolution as descriptors, per-label policy |
| `system.Notify` | BSDNotify | Publish/subscribe with state cells and timers; a second name, `system.Notify.System`, is gated by an anointment |
| `system.Power` | BSDPower | ACPI sleep states (reboot and halt stay with capsule) |
| `system.Sysctl` | BSDSysctl | Reads and writes sysctl OIDs through the sysctl gate; sole writer of isolated OIDs such as `kern.maxfiles` |
| `system.Time` | BSDTime | Reads, steps and slews the clock through the settime gate |
| `system.Trace` | BSDTrace | Delivers a rights-limited DTrace descriptor to anointed callers |
| `system.VM` | BSDVM | The virtual-machine authority; today a vsock endpoint broker with label-scoped port windows, running ambient |
| `system.Bluetooth` | BSDBluetooth | The BLE host (GAP, GATT, ATT, SMP, ISO, HOGP) as a provider, with domain-multiplexed operations |

Two names that a reader will meet in logs are not among the sixteen because
they belong to the runtime itself: `system.switchboard` is switchboard's own
control endpoint (switchboardctl(8)) and `system.lifecycle` is the
ADMIN-gated lifecycle endpoint switchboard exposes and relays to capsule
(capsulectl(8)).

## What 5BSD is not

It is not a system in which root has been abolished. Root still exists on the
BSD side and several providers run as root because the facility they broker
requires it. What has changed is that root is not consulted when a plane
service decides whether to act, and the management model lets a CORE unit
resist even root. The book calls this least privilege, never a seal.

It is not a distribution of FreeBSD with extra packages. The kernel differs
(the plane is compiled into GENERIC as `standard`), PID 1 differs, the service
manager differs and the login path differs. Those differences are contained,
and every one of them has a documented way back: `capability_plane="NO"` at
the loader boots the stock init(8) on the same disk.

It is not finished. The divergence inventory records which pieces are
shipped, which are in progress and which are design-only, and every chapter
in this book repeats that verdict for its subject.

**Status.** Checked against the `dev` branch on 2026-09-25. The counts above
are from `docs/5bsd-inventory.md` of the same date. Verified execution is
present but not enforcing; Linux seccomp and Landlock are uncommitted work in
progress; BSDVM is the only ambient provider and does not yet run virtual
machines.
