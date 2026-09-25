# Troubleshooting

Most 5BSD failures have a FreeBSD-shaped symptom and a plane-shaped cause: a
daemon that "will not start" is a unit switchboard could not launch, a
"permission denied" inside a daemon is capability mode doing its job, a test
that "cannot open a device" is running on a plane that already owns it. This
chapter is organised by symptom. Each entry gives the cause, what to look at
and the commands to run, and the fix. Two files carry most of the evidence:
`/var/log/messages`, where switchboard logs with the `switchboard` tag, and
`/var/log/capability.log`, the shared stdout and stderr of every unit
switchboard launches (opened by switchboard as root before the unit enters
its sandbox, so a daemon that can reach nothing else can still write there).
`switchboardctl status` and `switchboardctl services` show the live view.

## A unit failed to launch

**Symptom.** `switchboardctl services` does not list a unit you expect;
`/var/log/messages` has `switchboard: startup: failed to launch
'<label>'`, or later `service <label>: exec failed N times, disabling`. A
client of that unit reports `service_open` timing out (next entry).

**Cause.** The unit's process exited before switchboard considered it
running, or could not be exec'd at all. Common reasons, roughly in order:
the program aborted in its own startup (missing configuration, a library it
cannot load from the bundle's `lib/`), a resource in the manifest's
`directories` list does not exist so switchboard could not deliver the
descriptor, the unit's `user` does not resolve (a fresh root whose
`pwd.db` was never regenerated), or the root filesystem was still read-only
when the unit's launch container was created.

**Check.**

```sh
grep 'switchboard' /var/log/messages | grep -e 'failed to launch' -e 'disabling' -e "'<label>'"
tail -100 /var/log/capability.log         # the unit's own stderr, in launch order
switchboardctl verify /Capabilities/System/<Name>.cap
switchboardctl deps /Capabilities/System/<Name>.cap/Units/<unit>.unit/bin/<program>
```

`verify` validates the bundle and every manifest with the same parser
switchboard uses; `deps` lists the shared libraries the program needs and
whether the bundle or the base provides them. A launch that reached the
program prints the program's own diagnostics to `capability.log`; a launch
that did not shows only switchboard's line.

**EROFS at boot** is a specific case worth naming. Switchboard creates each
unit's launch container under `/Capabilities/Run` before exec. On an
installed system that directory is a tmpfs mount from fstab, so it is
writable as soon as the mount happens; on a hand-built image without that
fstab line it is a directory on the root filesystem, which stays read-only
until `/etc/rc` remounts it. If `/etc/rc` never ran (an image staged without
`make distribution`, so `/etc/rc` and `rc.d` are missing), every
`mkdir` fails with `EROFS`, switchboard logs `startup: launched 0 native
services`, and the console stops before a login prompt. Confirm with
`mount | grep ' / '` (look for `read-only`) and `ls /etc/rc /etc/rc.d | head`.

**Fix.** Address the cause the log names, then `switchboardctl start
<label>` (which also resets the restart backoff) or `switchboardctl
reload` after editing a manifest. For the EROFS case, add the tmpfs line to
`/etc/fstab` and, on a from-source image, stage with `installworld
distribution installkernel`. Labels are `<bundle_id>/<unit>` (for example
`system.Log/bsdlog`).

## `service_open` times out or returns ENOENT

**Symptom.** A client blocks for a while and then fails with `ETIMEDOUT`, or
fails at once with `ENOENT`, on `service_open("system.X")` or a tool such as
`sysctlcmpctl get kern.ostype`; a provider logs `timed out waiting for
system.Log` and, after enough retries, `failed N times, disabling`.

**Cause.** Lookups go over the caller's ambient lookup channel to
switchboard, which answers only for names that are visible to the caller's
domain and whose unit has activated. `ENOENT` means one of: the process has
no lookup channel (it was started outside a session or a unit, for example
from an rc script that scrubbed its descriptors), the name is not published
by any loaded bundle, the name is `visible` only to the `system` domain and
the caller has a `user` session, or the name requires an anointment the
caller's session does not hold (`system.Trace` requires
`system.trace.client`, and the reply is deliberately `ENOENT`). A timeout
means switchboard accepted the name but the provider did not come up within
`SERVICE_LOOKUP_TIMEOUT_MS` (2 seconds per attempt; clients built on
libservice retry): the unit is still starting (BSDFilesystem's cold start can
take longer than that on a fresh pool), it failed to launch (previous entry),
or, for a provider that runs with ambient authority, its manifest forgot
`ambient = true` so switchboard launched it sandboxed and it never answered.

**Check.**

```sh
switchboardctl services                          # is the provider listed, and in what state?
switchboardctl graph --lint                      # unreachable endpoints, dead declarations
grep -e 'on_demand' -e "'system.X'" /var/log/messages
env | grep SERVICE_LOOKUP_FD                     # does this process even hold a channel?
switchboardctl verify /Capabilities/System/<Name>.cap
```

`graph --lint` reports a name nothing provides or nothing can reach.
`verify` catches a manifest whose `activation.ipc` block does not declare
the name you are asking for.

**Fix.** Publish the name (`activation { ipc = [ { name = "system.X"; } ] }`
in the provider's unit manifest), make it visible to the right domain
(`visible = ["system", "user"]`), give the caller the anointment
(`anoint <name> <command>` for one run, or a `holds` entry for a unit), and
for slow providers let the client's retry run rather than treating the first
timeout as fatal. Components must fail soft when a provider is down; see
[Discovery and the Lookup Channel](../plane/discovery-and-lookup.md).

## EPERM or ECAPMODE inside a daemon

**Symptom.** A unit starts, then logs `Operation not permitted` or `Not
permitted in capability mode` (errno 94, `ECAPMODE`) from `open`, `socket`,
`connect`, `sysctl` or `syslog`; or its log lines vanish altogether.

**Cause.** The unit is born in capability mode: switchboard enters
`cap_enter(2)` before `fexecve`, so the program has no global namespace. It
cannot `open("/etc/anything")`, cannot reach `/var/run/log` (so `syslog(3)`
is silently lost), cannot `sysctl` unless it holds the `system` gate, and
cannot look up names in `/etc/passwd`. `EPERM` from a capability provider's
reply (rather than from a syscall) means the caller's label is not in that
provider's policy.

**Check.**

```sh
procstat -s <pid>                                # FLAGS shows C for capability mode
procstat -f <pid>                                # which directory descriptors it holds
grep -A3 '^directories' /Capabilities/System/<Name>.cap/Units/<unit>.unit/Unit.ucl
tail /var/log/capability.log
```

**Fix.** Use the plane's substitutes. Configuration files go in the unit's
`Config/` directory and are opened with `service_config_open(name, &fd)`,
which openat's under the delivered descriptor; data directories are declared
in the manifest's `directories` list and arrive as descriptors; devices are
brokered by `system.Device`; sysctls by `system.Sysctl`; name resolution and
sockets by `system.Network`; and logging goes through `logcmp_log(3)` (a
capability-mode-safe `syslog(3)` that emits to `system.Log` and falls back
to syslog while the plane is coming up). A daemon that must keep ambient
authority declares `ambient = true` and accepts that it is not sandboxed.
The full list of substitutes is in
[Capability Mode and the Born-Sandboxed Launch](../capability/capability-mode-and-launch.md).

## Tests fail with EPERM on /dev/mac_capability

**Symptom.** `kyua test` in `/usr/tests/sys/mac_capability` or a daemon's
`session_test` fails every case with `open(/dev/mac_capability): Operation
not permitted`, or `run_tests.sh` stops with `A live capability plane is
running (PID 1 = capsule)`.

**Cause.** On a normal boot capsule claims the control device and holds it
for switchboard; nothing else may open it. The kernel suites, and the daemon
suites that fork their own provider, need to be the claimant.

**Check.** `ps -p 1 -o comm=` prints `capsule`; `ls -l /dev/mac_capability`.

**Fix.** Boot plane-free: `set capability_plane="NO"` at the loader prompt,
or `capability_plane="NO"` in `/boot/loader.conf`. Capsule execs stock init
and nothing claims the device. The in-tree rig builds such an image with
`CAPLANE_OFF=1` (`tools/test/capability-containers/rig/build-image-authority.sh`).
Changing `init_path` does not work: capsule is still PID 1 and still claims
the plane. Suites that need the plane *up* (capsule, switchboard, the
container proofs) need the opposite image; the tiers are in
[Testing](../develop/testing.md).

## `pkg install` of a bundle did nothing

**Symptom.** A package that ships a `.cap` bundle installed cleanly, but
`switchboardctl services` does not show its units and nothing was launched.

**Cause.** Switchboard learns about bundles two ways: a full scan at boot,
and a kevent watch on the install folders `/Capabilities/System` and
`/Capabilities/Apps` (and on each bundle directory under them). A change
arms a settle timer (2 seconds; `SWITCHBOARD_REGISTRY_WATCH_SETTLE` in
switchboard's environment overrides it, up to 60) and one reload follows
the last change. If the bundle went anywhere
else, if `/Capabilities/Apps` did not exist when switchboard started (it
watches the parent and re-arms when the folder appears), if the package
was still extracting when the scan ran (it is quarantined and rescanned up
to eight times), or if the manifest failed validation, no unit appears.

**Check.**

```sh
grep 'registry:' /var/log/messages     # "watching install folder", "install folders changed; reloading"
grep 'reload:' /var/log/messages       # "reload: N new, N changed, N removed"
switchboardctl bundles
switchboardctl verify /Capabilities/Apps/<Name>.cap
```

**Fix.** Put the bundle under one of the two install folders;
`switchboardctl reload` to force a rescan now; `switchboardctl install
path.cap` to copy and register a bundle from elsewhere; fix whatever
`verify` reports. A unit with `activation { boot = true; }` starts on
reload; an on-demand unit starts at first lookup. Persistent storage for a
new bundle is reconciled by the providers on their next pass, which
`reclaimstat` shows; see
[Containers and Storage](../plane/containers-and-storage.md).

## A Linux binary fails with ENOSYS

**Symptom.** A Linux program prints `Function not implemented`, or the
console and `dmesg` show `linux: jid 0 pid 1234 (name): syscall foo not
implemented`.

**Cause.** The Linuxulator fills the Linux amd64 table with named stubs
that return `ENOSYS` for calls it does not implement
(`sys/compat/linux/linux_dummy.c`); `compat.linux.debug` (default 3) makes
each first use log the line above. Either the call is one of those stubs
(`io_uring` is not: it is implemented over squeue), or the binary is 32-bit
(5BSD has no 32-bit `linux` module) or was not branded.

**Check.**

```sh
dmesg | grep '^linux:'
file ./program                         # ELF 64-bit ... for GNU/Linux
sysctl compat.linux.osrelease
truss -f ./program 2>&1 | grep -e ENOSYS -e 'not implemented'
```

**Fix.** For a stubbed call there is no fix short of implementing it;
[System Calls](../compat/linux/syscalls.md) has the coverage table.
For a 32-bit binary, obtain the 64-bit build. For an unbranded one,
`brandelf -t Linux ./program`. Note that Linux seccomp and Landlock support
is in progress and not shipped; a program that requires them at startup
fails at those calls rather than with the message above, and the state of
that work is in [Sandboxing and Debugging](../compat/linux/sandboxing.md).

## `top` shows every daemon as `ld-elf.so.1`

**Symptom.** On an older kernel, `top`, `ps` and `pgrep` show the plane's
units as `ld-elf.so.1` rather than `BSDLog`, `BSDNetwork` and so on, and
`pgrep -x BSDLog` finds nothing.

**Cause.** Before `kern.elf64.capmode_interp` existed, a process in
capability mode could not exec a dynamically linked binary, so switchboard
launched units through `ld-elf.so.1 -f <fd>`; the exec'd image, and
therefore `p_comm`, was the run-time linker. The kernel now allows a
capability-mode exec to load the brand's own interpreter, and switchboard
`fexecve`s units directly.

**Check.** `sysctl kern.elf64.capmode_interp` should print `1`; `uname -v`
shows the kernel build; `pkg info 5BSD-kernel-generic` the package. On a
current kernel with the knob set to `0`, units fail to launch instead of
showing the old name.

**Fix.** Upgrade the kernel package and reboot, and make sure the knob is
not set to `0` in `/boot/loader.conf` or `/etc/sysctl.conf`.

## Stale kernel modules versus packages

**Symptom.** After `pkg upgrade` from a repository you built, a gate
provider (BSDSysctl, BSDPower, BSDTime, BSDExtension, BSDFilesystem)
crash-loops with `Operation not permitted` from a syscall it is supposed to
have a gate for, `kern.mac_capability_isolation.auth_count` stays low, or
`kldload` of a module reports a version mismatch.

**Cause.** `make packages` cuts the kernel and every module package from
the kernel build tree, which `buildworld` never touches. A repository built
after a `buildworld` without a `buildkernel` ships modules from the previous
kernel build; a gate consumer built against the new kernel then meets an
old gate implementation. The mtime-based incremental kernel build can also
skip a module whose sources a `git checkout` made older than the object.

**Check.**

```sh
uname -v                                  # build date of the running kernel
pkg info -l 5BSD-kernel-generic | head    # what the package installed
ls -l /boot/kernel/kernel /boot/kernel/linux64.ko   # do dates agree?
sysctl kern.mac_capability_isolation.auth_count
```

**Fix.** On the build host: `make buildkernel` (after `touch`ing the
suspect sources if the incremental build skipped them), then `make packages
PKG_CMD=/usr/local/sbin/pkg-static` again; on the target, `pkg upgrade -r
5BSD` and reboot. This is the same class of failure as an old daemon binary
under a new libservice, which shows up as a stack-protector abort at
startup; the cure is the same, a consistent world and kernel from one build.

## Where else to look

| Evidence | Where |
|---|---|
| switchboard and capsule decisions | `/var/log/messages` (tags `switchboard`, `capsule`); `/usr/share/dtrace/switchboard-*` and `capsule-*` scripts live |
| Unit stdout/stderr | `/var/log/capability.log` |
| Structured records | `logctl show`, `logctl stats` |
| Audit trail | `praudit /var/audit/current` |
| Kernel-side capability denials | `dtrace -s /usr/share/dtrace/mac_capability-denials` |
| Provider storage reconciles | `reclaimstat -a` |
| Anointment reach | `switchboardctl graph --lint` |

See [Observability](observability.md) for the tools and
[Tool Reference](tools.md) for what each command is.
