# Capability Mode and the Born-Sandboxed Launch

Capability mode is Capsicum's sandbox: after `cap_enter(2)` a process can
use only the descriptors it holds and can never again name anything in a
global namespace. FreeBSD leaves it to each program to enter the sandbox
after its own setup, which means every daemon has an un-sandboxed startup
window. 5BSD closes that window: switchboard enters capability mode itself
and then executes the unit's program, so a service's first instruction
already runs confined. This chapter explains what capability mode forbids,
how the launch works, the one kernel rule that makes dynamic binaries
possible under it, and what a freshly born process can and cannot do.

## What capability mode forbids

The rules are FreeBSD's, documented in capsicum(4) and cap_enter(2); this
book does not restate them. In short: no path-based opens except relative to
a held directory descriptor (`openat(2)` and the other `*at(2)` calls, with
the lookup confined beneath that directory), no process operations by PID
except on the process itself, no new global-namespace objects, and only
system calls marked `CAPENABLED` in `sys/kern/syscalls.master`. Every held
descriptor is further bounded by its Capsicum rights, ioctl allowlist and
fcntl mask. A process that attempts a forbidden call gets `ECAPMODE`, or
`ENOTCAPABLE` when the descriptor's rights are the problem; with
`PROC_TRAPCAP_CTL` enabled the violation also raises `SIGTRAP`, which is the
quickest way to find a stray path open in a new daemon.

5BSD adds three things to the syscall side. `SYF_CAPREQUIRED` is a new
syscall flag meaning the call is legal only inside capability mode and
returns `ENOTCAPABLE` outside it; it implies `CAPENABLED`, and today only
`pdself(2)` carries it. `reboot(2)`, the `kld*` family, `auditon(2)` and
`jail_attach_jd(2)`/`jail_remove_jd(2)` are now `CAPENABLED`, gated by held
claims in the `system` service instead of by being unreachable
([System Gates](system-gates.md)). And the `mac_proc_check_syscall` hook
runs at dispatch, so a MAC policy can veto a call before its handler.
Sockets gained `LOCAL_CAP_REQ`, `LOCAL_CAP_CONNECT` and
`LOCAL_CAPMODE_SERVER` for mutual attestation between sandboxed peers, and
a capability-mode process can bind and connect INET sockets it already
holds; see [Descriptor and Process Protections](descriptor-protections.md).

## The launch

`usr.sbin/switchboard/execute.c` launches a native unit. The parent has
already minted the unit's service channel, coalition and (if the manifest
has a `protect` list) a capprotect instance from capsule, and confined each
to itself. Then it calls `pdfork(2)` with `PD_CLOEXEC`, and the child does
the following, in order, still running as root:

| Step | What happens |
|---|---|
| stdio | fd 0 from `/dev/null`; fd 1 and 2 to a switchboard diagnostic log so early failures are visible |
| fd 3 | the unit's service channel (`SVC_CHANNEL_FD`) |
| fd 4 | the capprotect instance, when one exists (`SVC_CAPPROTECT_FD`) |
| fd 5 | the bootstrap descriptor: an envfd named `org.5bsd.switchboard.bootstrap`, written once and sealed, `CAP_XFER_NONE`, `CAP_CLOFORK_ONCE`, `CAP_CLOEXEC_ONCE` (`SERVICE_BOOTSTRAP_FD`) |
| fd 6 and up | system-gate tokens and delivered capabilities named in the bootstrap (`SVC_TOKEN_BASE`) |
| `closefrom(2)` | everything else is closed; then the descriptors that must cross the exec have `FD_CLOEXEC` cleared |
| environment | `SERVICE_BOOTSTRAP_FD=5`, `CAPABILITY_UNIT_DIR=<unit dir>`, the manifest's `environment`, `USER` and `HOME` |
| libraries | `/lib` and `/usr/lib` opened `O_DIRECTORY`, plus the bundle's `lib/` when present, published as `LD_LIBRARY_PATH_FDS=<fd>:<fd>[:<fd>]` |
| config | the unit's `Config/` directory, when present, opened read-only and published as `CAPABILITY_CONFIG_FD=<fd>` |
| resources | each manifest `directories` entry opened `O_DIRECTORY` and published as `path=fd` pairs in `CAPABILITY_DIR_FDS` |
| program | `open(program, O_EXEC \| O_VERIFY)` while the launcher can still traverse the sealed bundle tree (verification strips permission bits from bundle directories) |
| container | `chdir` into the unit's per-instance run container |
| policy | `setrlimit` from `limits {}`, `nice` from `level`, `umask`, then `setgroups`/`setgid`/`setuid` to the manifest `user` and `group` |
| signals | every disposition reset to default, mask emptied |
| sandbox | `cap_enter()`; a failure is fatal (`_exit(126)`) |
| exec | `fexecve(tgtfd, argv, env)` |

The parent, meanwhile, enlists the child's process descriptor in the
coalition and makes it the leader, applies the manifest `protect` flags with
`CP_OP_PROTECT` while the descriptor is still transferable, samples
`pdincapmode(2)`, and watches `EVFILT_PROCDESC` for `NOTE_CAPMODE`. The unit
is `STARTING` until the kernel reports it in capability mode and its
`provides` names are claimed; only then is it `RUNNING`
([Switchboard](../plane/switchboard.md)). An `rc` unit or a one-shot command
takes a different path: `execve(2)` by path, no `cap_enter`, a clean
descriptor table, judged by exit status. A unit whose manifest says
`ambient = true` is likewise executed by path without a sandbox; it is the
deliberate exception for work that needs the global namespace, and the
inventory's daemon scorecard records BSDVM as the only system unit launched
that way.

## The kernel rule for dynamic binaries

A dynamically linked ELF image names its interpreter in `PT_INTERP` as an
absolute path. Loading it from capability mode was refused outright in
FreeBSD (`__elfN(load_file)` returned `ECAPMODE`), which is why sandboxed
daemons had to be static or had to exec before sandboxing. 5BSD's
`sys/kern/imgact_elf.c` allows exactly one path lookup on behalf of a
capability-mode process: when the image's `PT_INTERP` string is identical
to the matched ELF brand's own `interp_path` (a fixed, kernel-known string,
`/libexec/ld-elf.so.1` for the native brand), the interpreter is looked up
with `NOCAPCHECK`. Any other `PT_INTERP`, including a working private copy
of rtld or a path that merely starts with the brand's, still fails with
`ECAPMODE` before any lookup happens. The rule is gated by
`kern.elf64.capmode_interp` (and `kern.elf32.capmode_interp`), a boolean
tunable and sysctl that defaults on; set it to 0 and capability-mode exec
of dynamic images is closed again. Static images are unaffected.

Once rtld is running it resolves the program's `NEEDED` libraries, and any
later `dlopen(3)`, from the directory descriptors in `LD_LIBRARY_PATH_FDS`
by `openat(2)`, never by path. rtld honours that variable only for trusted
launches (`issetugid(2)` false), which the switchboard child is. The
delivered descriptors are `/lib`, `/usr/lib` and the bundle's own `lib/`,
in that order, so a bundle ships only its private libraries.

`tests/sys/kern/capmode_interp_test.c` proves each edge with three helper
images: the brand interpreter works from capability mode and the process
carries the helper's own command name; a private copy of rtld named in
`PT_INTERP` is `ECAPMODE`; a missing interpreter and a brand-prefixed
path are `ECAPMODE`; the knob closes the door; and the un-sandboxed control
run of each case behaves as before. An earlier experiment did the same job
without a kernel change by having switchboard exec the static rtld with
`-f <fd>`; it worked, but every unit then appeared as `ld-elf.so.1` to
top(1), ps(1), pgrep(1), audit and core naming, and the kernel's exec-time
veriexec check never saw the program. That is why the narrow kernel rule
was chosen (`docs/book/src/capability/capability-mode-and-launch.md` records the
decision): because the kernel executes the program itself, the process
carries the program's own `p_comm` and `AT_EXECPATH`, and
[Verified Execution](veriexec.md) sees the real image.

## What a born-sandboxed process can do at its first instruction

It can use what it holds, and only that.

| It can | Because |
|---|---|
| read its bootstrap and learn its label, channel, tokens and delivered capabilities | fd 5 is a sealed envfd; libservice(3) parses it in `service_acquire()` and verifies name, seal and size |
| talk to switchboard and resolve services lazily | fd 3 is its channel; `service_open()` and the typed client libraries acquire providers over the lookup channel on first use |
| load and `dlopen` its libraries | `LD_LIBRARY_PATH_FDS` directory descriptors |
| open its configuration | `service_config_open(3)` does `openat` under `CAPABILITY_CONFIG_FD` |
| reach declared resource directories such as a `/dev` subtree | `service_resource_dir(3)` over `CAPABILITY_DIR_FDS` |
| create private channel pairs | `mac_capability_channel_create(2)` is `CAPENABLED` |
| do gated privileged work | a delivered system-gate token and the `system` service's perform ops ([System Gates](system-gates.md)) |
| obtain storage, a jail, a kernel module, a vsock port | self-service through BSDFilesystem, BSDNamespace, BSDExtension and BSDVM over its channel, never by declaration ([Containers and Storage](../plane/containers-and-storage.md)) |

| It cannot | Because |
|---|---|
| open anything by path, `connect(2)` to a socket path, or read `/etc` | capability mode |
| open `/dev/mac_capability` or connect to a kernel service by name | the device is claimed by capsule and unreachable by path anyway |
| signal, trace or wait for another process by PID | capability mode; process descriptors are the only handle |
| exec another dynamic program by path | it can `fexecve(2)` a held executable descriptor, whose interpreter must again be the brand's |
| call `syslog(3)` and expect delivery | the socket path is unreachable; capability-mode units log through `logcmp_log(3)` and system.Log ([Logging, Audit and Trace](../plane/logging-audit-trace.md)) |
| widen anything | rights, ioctl allowlists, transfer and propagation states only tighten |

The consequence for a daemon author is that all setup that needs the
global namespace has to have been done by switchboard and expressed as a
delivered descriptor. There is no "before `cap_enter`" in a native unit.
Units that need privileged primitives get them as held gate tokens
(BSDTime, BSDSysctl, BSDExtension, BSDNamespace, BSDPower) rather than by
running un-sandboxed; the plan in
`docs/book/src/capability/capability-mode-and-launch.md` is to retire libcasper
from daemons on the same principle, by concentrating privilege in the
system providers. That retirement is the plan's end state, not its current
one: `lib/libcasper` is still in the tree and still used outside the plane.

## Debugging a launch

A unit that dies at exit code 126 failed inside the child before exec: a
descriptor could not be placed, a limit could not be applied, the program
could not be opened, or `cap_enter` failed. Exit 127 means `fexecve` itself
failed, which with a dynamic program almost always means a `PT_INTERP` the
kernel refused. switchboardctl(8) reports the unit state; the diagnostic
log carries the child's stderr; `dtrace -n 'syscall:::return /errno ==
ECAPMODE || errno == ENOTCAPABLE/ { @[execname, probefunc] = count(); }'`
finds the first forbidden call a new daemon makes, and
`share/dtrace/capsicum-denials` packages that. Set
`kern.elf64.capmode_interp=0` only to prove a fleet is static-clean; with
it off, every native unit fails to launch.

## Status

Shipped: born-in-capability-mode launch for every native unit, the
delivered-descriptor contract (fds 3, 4, 5, 6+, `LD_LIBRARY_PATH_FDS`,
`CAPABILITY_CONFIG_FD`, `CAPABILITY_DIR_FDS`), the kernel interpreter rule
with its test (bb570c54f061), `SYF_CAPREQUIRED` and the `CAPENABLED`
marking of the gated syscalls, all VM-verified on a production plane.
Open: BSDVM still launches ambient; libcasper retirement remains a plan.
