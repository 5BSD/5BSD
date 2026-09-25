# How to Read a Provider Chapter

A system capability provider is a daemon that owns one facility (storage,
logging, crypto, the clock) and publishes it under one well-known wire name
such as `system.Log`. 5BSD has sixteen of them. They exist so that no
program needs root, a device node, or a socket path merely to use a system
facility: the program holds a channel to the provider, and the provider
holds the resource. Part IV is the reference for those sixteen daemons.
This chapter explains the template every provider chapter follows, the
client pattern they all share, and how to read their operation tables.

## The template

Each provider chapter has the same eight sections, in the same order, so a
reader can compare two providers side by side.

| Section | What it answers |
|---|---|
| What it brokers | Which resource the daemon holds on the caller's behalf, and why that resource is not ambient |
| Unit | The unit manifest: wire name, program path in the bundle, unit name, user, launch mode, declared gates, restart policy, `protect` set |
| Wire operations | Every op in the protocol header: request, reply, errors, and the version handshake |
| Client library | Header, link flag, every public function, one compiling example |
| Command-line tool | The operator ctl verbs, with invocations and output shape |
| Policy | The provider's policy file or per-label rules, what is denied by default, and whether admin sessions bypass it |
| Tests | Where the ATF programs live, how to run them, what they prove |
| Status and gaps | What the divergence inventory records as shipped, deferred, or missing |

The Unit section is transcribed from the daemon's
`usr.sbin/BSD*/capbundle/*.ucl`, which is installed as
`/Capabilities/System/<Name>.cap/Units/<unit>.unit/Unit.ucl`. When a table
cell says "default", the manifest omits the key and libcapbundle supplies
the value: `user` defaults to `capability`, `ambient` to false (born in
capability mode), `visible` to system-domain lookups only. The key set and
its limits are in [Bundles and Manifests](../plane/bundles-and-manifests.md).

## The common client pattern

Every provider is a socket-free `service_provider` built on libservice(3).
There is no AF_UNIX socket and no path to name. A client reaches a provider
by calling `service_open(3)` with the wire name; libservice resolves the name
over the per-process lookup channel that switchboard installed at launch
(or, for a program run from a login shell, over the ambient lookup channel
the session inherited at `SERVICE_LOOKUP_FIXED_FD`), and the result is a
held mac_capability channel to a worker inside the provider. The mechanics
of that lookup are in [Discovery and the Lookup
Channel](../plane/discovery-and-lookup.md).

```c
#include <libservice.h>

int session_fd;

if (service_open("system.Time", &session_fd) != 0)
        err(1, "system.Time");
```

The typed client libraries (`liblogcmp`, `libcryptocmp`, `libauditcmp` and
the rest) wrap that call in a `*_client_open()` or `*_open()` function and
carry the wire structs, so a consumer never assembles a message by hand.
Four conventions hold across all of them.

**Lazy acquire.** A client opens its channel on first use, not at startup.
A unit that logs, for instance, does not fail to launch because `system.Log`
has not checked in yet; the first `logcmp_log(3)` call resolves the name and
the lookup parks until the provider is ready or `SERVICE_LOOKUP_TIMEOUT_MS`
(2000 ms) elapses.

**Fail soft.** A provider that is down, not yet launched, or refusing the
caller is reported as an error to the calling function (`-1` with errno, or
a nonzero return), never as a process exit. `logcmp_log(3)` goes further and
falls back to syslog(3) when `system.Log` is unreachable; storage requests
treat a silent worker as a dead session and reopen on the next claim
(`SERVICE_STORAGE_CALL_TIMEOUT_MS`, 10 s). The rule is stated in [Choosing
What to Write](../develop/choosing.md): components ask for a capability at
the point of use and degrade when the answer is no.

**Cached channel.** A `struct *_client` owns one session channel and is
reused for every call until `*_close()`. Providers serve each channel from
a dedicated worker (a pdfork(2) child or a shard of a fixed pool), so the
channel is also the unit of isolation on the provider side: what one client
can do is bounded by the label switchboard stamped on its channel, and the
provider reads that label from the kernel, never from the payload.

**HELLO and ABI negotiation.** Most protocols begin with a version
handshake. The typed libraries send it inside `*_open()` so a mismatched
client and provider fail at open time rather than on the first real call.
The shapes differ per protocol and the chapters say which applies:

| Shape | Providers |
|---|---|
| Bare HELLO carrying a magic and ABI version, empty reply on match | system.Crypto (op 11), system.Time, system.Power, system.Sysctl |
| HELLO header answered with a reply that states the provider's version (and, for Notify, its features and limits) | system.Audit (ABI 1), system.Device, system.Notify |
| HELLO with `min_version`/`max_version` and a feature bitmap, reply selects the version | system.Log (ABI 6, `LOGCMP_FEATURE_*`), system.Network |
| A `version` field in every request; the daemon accepts a minimum version | system.Auth (`AUTHAGENTD_PROTO_VERSION` 3, minimum 2) |
| No handshake; the request's `op` field is the whole contract | system.Filesystem (`BSDFILESYSTEM_PROTO_VERSION` 6 is a header constant, not sent on the wire), system.Namespace, system.SystemExtension, system.VM |

## Reading the ops tables

An operations table lists every opcode from the protocol header in numeric
order. The **request** and **reply** columns name the wire struct (or "bare
header" when only the fixed message header travels). When a reply carries a
file descriptor, the table says so: providers deliver descriptors with
SCM_RIGHTS on the channel, never as integers in the payload, and the
descriptor arrives already narrowed to the rights the request asked for.
The **errors** column lists the errno values the daemon returns in the
reply's `status` field, in the order the daemon checks them where that
order matters (BSDAuth's elevation path is the clearest example). An
error the table does not list is a transport failure, which the client
library maps to its own errno: `ECONNRESET` for a worker that died,
`ETIMEDOUT` for a wedged one.

Two things never appear in a request. The caller's identity is not a wire
argument: every owner-scoped operation (a storage claim, a named key, a log
query) resolves the owner from the channel label. And a request never
carries a path to a resource the provider holds; it names a claim, a key,
or a topic inside the caller's own scope.

## The sixteen providers

| Wire name | Daemon | Client library | Ctl tool | Launch mode |
|---|---|---|---|---|
| system.Filesystem | BSDFilesystem | libbsdfilesystem, libtrustedzfs, libservice storage API | tzfsctl(8) | born in capability mode, root |
| system.Log | BSDLog | liblogcmp | logctl(8) | born in capability mode, `capability` |
| system.Audit | BSDAudit | libauditcmp | none | born in capability mode, root |
| system.Auth | BSDAuth | libservice (`service_mint_session_via_agent`, `service_elevate`) | anoint(1) | born in capability mode, root |
| system.Crypto | BSDCrypto | libcryptocmp (and libcryptodesc for the descriptor ioctls) | none | born in capability mode, root |
| system.Network | BSDNetwork | libnetworkcmp | networkcmpctl(8) | born in capability mode, `capability` |
| system.Device | BSDDevice | libdevicecmp | none | born in capability mode, `capability` |
| system.Notify, system.Notify.System | BSDNotify | libnotify | notifyctl(8) | born in capability mode, `capability` |
| system.Sysctl | BSDSysctl | libsysctlcmp | sysctlcmpctl(8) | born in capability mode, `capability`, gate `sysctl` |
| system.Time | BSDTime | libtimecmp | BSDTimectl(8) | born in capability mode, `capability`, gate `settime` |
| system.Power | BSDPower | libpowercmp | BSDPowerctl(8) | born in capability mode, `capability` |
| system.SystemExtension | BSDExtension | libservice (`service_ensure_extension`) | sysextctl(8) | born in capability mode, `capability`, gates `kldload`, `kldunload` |
| system.Namespace | BSDNamespace | libservice (`service_enter_namespace`) | none | born in capability mode, `capability`, gate `jail`, on demand |
| system.Trace | BSDTrace | libtracecmp | tracectl(8) | born in capability mode, root, requires anointment `system.trace.client` |
| system.VM | BSDVM | libservice (`service_vsock_listen`, `service_vsock_connect`) | none | ambient, root, on demand |
| system.Bluetooth | BSDBluetooth | libble | bluedctl(8) | born in capability mode, `capability`, on demand |

Fifteen of the sixteen are born in capability mode: switchboard delivers the
directories the manifest names (`directories = [...]`) as descriptors,
delivers any Capsule-minted system gates the manifest declares
(`capabilities { system = [...] }`), and the daemon is in `cap_enter(2)`
before it serves its first client. BSDVM is the one `ambient = true`
provider; the [system.VM](vm.md) chapter records why. "On demand" means the
unit has no `boot = true` activation and switchboard launches it on the
first lookup of its name. Every unit in the table carries the same
`protect` set (`ptrace`, `signal`, `wait`, `sigkill`, `sigcont`, `sched`,
`core`, `ktrace`) and `restart = "on-failure"`, so the per-chapter Unit
tables only call out departures from that baseline.

## Where the rest is

The launch sequence that puts a daemon into capability mode before it runs
is in [Capability Mode and the Born-Sandboxed
Launch](../capability/capability-mode-and-launch.md). The gate tokens the
gate daemons hold are in [System Gates](../capability/system-gates.md). The
anointment names that `requires` refers to are in [Anointments and Principal
Policy](../plane/anointments.md). How to write a new provider on the same
pattern is [A Capability Provider](../develop/provider.md), and how to run
the ATF suites on a real plane is [Testing](../develop/testing.md).
