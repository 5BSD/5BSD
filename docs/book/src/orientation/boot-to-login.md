# From Power-On to Login

A 5BSD boot brings two systems up on one kernel: the capability plane, from
capsule through switchboard to the sixteen providers, and the classic rc
world, run by switchboard alongside its own units. This chapter narrates one
boot in the order the machine performs it and cites the log lines a reader
sees, so that the shape of a healthy boot is recognisable and a stalled one
can be placed. Operators reading for the knobs should continue to
[Boot Knobs](../operations/boot-knobs.md); this chapter is about the
mechanism.

## The loader

The FreeBSD loader is unchanged in code; the difference is in
`stand/defaults/loader.conf`. Two lines matter:

```sh
init_path="/sbin/capsule:/sbin/init:/sbin/init.bak:/rescue/init"
zfs_load="YES"
```

`init_path` puts `/sbin/capsule` first, with the stock init(8) and the rescue
init as fallbacks the kernel tries only if it cannot execute capsule at all.
The capsule package repeats the same line in
`/boot/loader.conf.d/capsule-loader.conf` so an upgrade of one without the
other stays bootable. `zfs_load` is unconditional because the storage plane
assumes a pool: `/dev/zfs` must exist for BSDFilesystem before rc(8) runs,
even on a host whose root is UFS. The same file loads `linux_common` and
`linux64`, so the Linux ABI is available from the first multi-user moment.
There are no `mac_capability` module loads: since the plane became `standard`
in `sys/conf/files`, every 5BSD kernel carries it.

One loader tunable is read by capsule rather than the kernel:
`capability_plane`. Its effect is described at the end of this chapter.

## Capsule, PID 1

The kernel executes `/sbin/capsule`. Running as PID 1, capsule
(`usr.sbin/capsule/capsule.c`) is a port of init(8)'s state machine with one
extra state, and it keeps init's contract: it never daemonizes, never exits,
reaps every orphan, and manages getty from `/etc/ttys`. Its first act is to
read the `capability_plane` kenv; if the plane is off it execs `/sbin/init`
and this chapter's plane half never happens. Otherwise it installs its signal
handlers, creates the kqueue that drives every later wait, honours
`init_script` and `init_chroot` as init(8) would, mounts devfs if the kernel
did not, and enters the state machine at `runcom`.

Here is the divergence. Stock init runs `/etc/rc` from `runcom`. Capsule's
`runcom` runs nothing; it records `rc startup delegated to switchboard` in
boottrace(4) and moves to `establish_capsule`. That state starts the
capability engine:

1. Load `/etc/capsule.conf` (optional; compiled-in defaults otherwise).
2. Verify that PID 1 already holds real-init reaper status.
3. Open `/dev/mac_capability` and claim it exclusively. From now on no other
   process can connect to the control device by name; everyone else receives
   delivered descriptors. Claim the network endpoints and system gates the
   configuration lists.
4. Raise the capprotect shield with the configured integrity flags. Signal,
   SIGKILL and SIGCONT protection from foreign programs are mandatory; PID 1
   cannot be signalled by an ambient `kill`.
5. pdfork(2) exactly one child, `/usr/libexec/switchboard`, with four
   delivered descriptors: the capsule channel at fd 3, a delegated channel
   service at fd 4, a delegated coalition service at fd 5 and a delegated
   capprotect instance at fd 6. The process descriptor capsule keeps is
   restricted to supervision rights and locked against transfer, fork and
   exec.

On success syslog shows:

```text
capsule: Capsule engine started; switchboard pid 27
```

Capsule then waits, with no deadline, for switchboard to report convergence
over its authenticated channel (`awaiting switchboard convergence` in
boottrace). `/etc/rc` has no knowable duration, so the only thing that ends
the wait early is switchboard dying permanently: its restart circuit breaker
trips after ten fast crashes, and capsule then drops to a single-user
recovery shell rather than leaving a multi-user system with no rc world.

The last thing capsule does before multi-user is receive a descriptor from
switchboard: a duplicate of the system ambient lookup channel. Capsule pins
it and, when it later spawns each getty, dup2(2)s it to fd 3
(`SERVICE_LOOKUP_FIXED_FD` in `lib/libservice/service_bootstrap.h`) with
close-on-exec cleared. The getty environment is hand-built and cannot carry
an environment variable across, so this one hop uses a fixed descriptor
number instead. Everything about the carry is best-effort: if it fails, getty
and login run with no channel and the boot is not gated.

## Switchboard

Switchboard (`usr.sbin/switchboard`) starts as root with the four inherited
descriptors, validates that the default unit identity exists and is what the
package promised, and shields itself:

```text
switchboard: default service identity validated: capability:capability uid=976 gid=976
switchboard: capprotect shield active
```

### The registry scan

Switchboard scans `/Capabilities/System` for system bundles, then
`/Capabilities/Apps` for installed application bundles, then each
`/Capabilities/Users/<uid>/Agents` for per-user agents. A bundle is a `.cap`
directory holding `Bundle.ucl` and `Units/<unit>.unit/Unit.ucl` with the
program under `bin/`. Directories and their contents must be root-owned and
not group- or world-writable; symlinks, undeclared units and unknown manifest
keys are rejected. A system bundle that fails to parse is fatal to the scan;
an application bundle that fails is quarantined and logged. Each accepted
bundle is one line:

```text
switchboard: bundle_registry: loaded 'Filesystem.cap' (1 services) [system]
switchboard: bundle_registry: loaded 'Log.cap' (1 services) [system]
...
switchboard: bundle_registry: 16 bundles loaded
switchboard: switchboard started, 16 bundles registered
```

Loading a bundle reserves every name its units declare in the naming
registry before any process runs, so a lookup has a stable activation target
from this point on. Then switchboard reaps runtime containers stranded by a
prior crash and moves to `startup_launch_system()` in `startup.c`.

### Boot units launch in parallel, and so does rc

Startup begins by recreating `/Capabilities/Run/live`, the tmpfs marker
directory that providers reconcile against, and collecting every unit whose
manifest says `activation { boot = true }`. Each is logged with its restart
policy, the names it provides and, for the gate daemons, the system gates its
manifest declares:

```text
switchboard: startup: loaded system.Filesystem/bsdfilesystem restart=on-failure
switchboard: startup: system.Filesystem/bsdfilesystem provides: system.Filesystem
switchboard: startup: loaded system.SystemExtension/bsdextension restart=on-failure
switchboard: startup: system.SystemExtension/bsdextension provides: system.SystemExtension
switchboard: startup: system.SystemExtension/bsdextension capabilities: system=0x3
switchboard: startup: 13 services loaded
```

Units carry no ordering. Every boot unit is launched at once:

```text
switchboard: startup: service: system.Filesystem/bsdfilesystem
switchboard: startup: service: system.Log/bsdlog
...
switchboard: startup: launched 13 native services
```

Only now does switchboard turn to rc. It mints the system ambient lookup
channel, installs it in its own environment as `SERVICE_LOOKUP_FD`, hands a
duplicate to capsule for the getty carry, and execs `/etc/rc` exactly as init
would have, as `sh /etc/rc autoboot`:

```text
switchboard: startup: system ambient lookup channel on fd 9
switchboard: startup: ambient lookup channel handed to capsule for logins
switchboard: startup: running /etc/rc
```

The native units are already coming up while rc runs. That is safe because a
born-in-capability-mode unit takes nothing from rc: its resources are the
descriptors switchboard delivered and the pool the loader imported, and
anything transiently unavailable is retried on demand. It is necessary
because rc.d scripts and their children inherit `SERVICE_LOOKUP_FD` and may
make synchronous lookups, which switchboard itself answers, so switchboard
drives its full event loop while it waits for rc rather than blocking on rc's
exit alone. When rc finishes, a curated set of rc.d services listed in
`/Capabilities/Config/switchboard/rc_adopt.conf` (cron, by default) is adopted
as supervised rc units, and startup closes:

```text
switchboard: startup: /etc/rc completed
switchboard: startup: launched 14 services
switchboard: startup: complete in 4312 ms
```

Switchboard then sends `CAPSULE_OP_READY` to capsule. Individual unit
failures do not block that; only switchboard's own death does.

### The born-in-capability-mode launch

Each native launch in `execute.c` is a pdfork(2). In the child, before any
credential drop, switchboard opens the verified program from the bundle, the
bundle's `lib` directory, the directories the manifest's `directories` array
names (for BSDFilesystem, `/` and `/dev`; for BSDLog, the two bundle roots
and `/Capabilities/Run/live`), and `/var/log/capability.log` as the unit's
stdout and stderr, since a sandboxed daemon cannot reach syslogd and boots
before `system.Log` exists. It applies `limits`, `umask`, `level` and the
`protect` shield from the manifest, sets the manifest `user` (default
`capability`), installs the sealed bootstrap envfd at fd 5 and the service
channel at fd 3, and then:

```c
if (cap_enter() == -1)
        _exit(126);
fexecve(tgtfd, argv, env);
```

The program is executed by descriptor inside capability mode. The kernel's
image activator loads the ELF interpreter for a capability-mode process only
when `PT_INTERP` names the brand's own rtld (`kern.elf64.capmode_interp`,
`sys/kern/imgact_elf.c`), and rtld then resolves the program's libraries by
openat(2) on delivered directory descriptors. There is no instant at which
the daemon runs unsandboxed, and because the kernel execs the program itself
the process carries its own name, not `ld-elf.so.1`. Switchboard watches the
process descriptor for `NOTE_CAPMODE` and moves the unit from STARTING to
RUNNING when the child confirms it is in capability mode and reports
`SVC_OP_READY`. Only a unit whose manifest says `ambient = true` (BSDVM) takes
the other branch, a plain execve(2) by path.

## The providers come up

Three providers matter most to what the rest of the boot can do.

**BSDFilesystem** (`system.Filesystem`) runs as root with delivered
descriptors for `/` and `/dev`. Its first work is `bsdfilesystem_layout_provision()`
in `usr.sbin/BSDFilesystem/layout.c`: open the pool root handle, ensure the
`zroot/Capabilities` dataset exists with `mountpoint=none` so the OS never
mounts the subtree (every dataset under it is reached only through anonymous
mounts on handles), ensure `zroot/Capabilities/Data` for persistent
containers and `zroot/Capabilities/ephemeral` for boot-scoped state, and
reconcile the boot generations. Then it reports ready and only afterwards
runs its boot garbage collection, so a herd of units asking for storage is
never blocked behind it:

```text
BSDFilesystem[41]: provisioned zroot/Capabilities {persistent,ephemeral}
```

That line lands in `/var/log/capability.log`. Every later `service_storage_open(3)`
from any unit is a request to this daemon for a handle under `Data/<bundle>/<unit>/`.

**BSDLog** (`system.Log`) runs as `capability`. It asks BSDFilesystem for its
own state container with `service_storage_open(3)` and keeps its segments
there; it is the reason a capability-mode unit can log at all, through
`logcmp_log(3)` rather than syslog(3). Until it is up, units write to the
diagnostic sink and retry.

**BSDAuth** (`system.Auth`) runs as root and is the only unit with
`mint_authority = true`. At startup it asks
BSDFilesystem to open `/etc/passwd`, `/etc/group` and
`/Capabilities/Config/principal-policy.ucl` on its behalf with
`service_open_isolated(3)`; nothing is declared in its manifest, and
BSDFilesystem's own per-label policy decides whether this label may read
them. An absent policy file is logged at INFO and the mint falls back to the
historical rule, root or `wheel` holds everything. Every login on the machine
will pass through this daemon.

The other boot providers (BSDAudit, BSDCrypto, BSDDevice, BSDExtension,
BSDNetwork, BSDNotify, BSDPower, BSDSysctl, BSDTime, BSDTrace) come up the
same way and wait for lookups. BSDNamespace, BSDVM and BSDBluetooth have no
`boot = true` and do not exist as processes until something resolves their
name.

## Meanwhile, rc

`/etc/rc` runs the rc.d sequence exactly as on FreeBSD: remount root
read-write, `/var`, networking, syslogd, devd, sshd and whatever
`/etc/rc.conf` enables. Three things differ. `auditd_enable` defaults to
`YES` so that `system.Audit` has something to commit to. The daemons that
5BSD moved onto the plane have no rc.d scripts, so nothing in rc starts a
provider twice. And every rc.d child inherits `SERVICE_LOOKUP_FD`, so a
classic daemon that links a 5BSD client library can reach a provider by name
without being a bundle. rc's own progress is written to the console as
always. See [rc and service(8)](../compat/rc-and-service.md).

## Convergence, getty and login

When capsule sees READY it records `switchboard converged` in boottrace,
re-asserts its signal shield, and moves to `read_ttys`. From here it is init:
it reads `/etc/ttys` and spawns a getty per line. One detail is 5BSD's: the
getty child receives the ambient lookup channel at fd 3, as described above.

login(1) (`usr.bin/login/login.c`) captures that channel before doing
anything else. `service_ambient_lookup_fd()` validates that fd 3 is an open
mac_capability channel (a stale or unrelated descriptor there is rejected),
login moves it to the fixed number if the environment named another, and then
`closefrom(4)` so nothing else inherited survives. Authentication is
unchanged: PAM, the password, the `login.conf` class. What follows it is new.
With the target uid known, login calls

```c
service_mint_session_via_agent(syschan, pwd->pw_uid, 0,
    SERVICE_MINT_SESSION_TIMEOUT_MS, &user_fd);
```

which sends a mint request over the system channel to BSDAuth. BSDAuth
resolves the principal against `/Capabilities/Config/principal-policy.ucl`:
uid 0 and members of `wheel` fall under `principals.admin` with
`anointments = ["*"]` and `admin_rights = true`, and receive a SYSTEM channel
that can resolve every name; every other user receives a per-uid USER
channel that resolves only names whose unit says `visible = ["user"]`
(BSDAuth, BSDFilesystem, BSDLog and BSDNotify among the providers). login
neither classifies the principal nor mints; direct minting over the ambient
channel is refused by switchboard. The returned descriptor is installed as
the session's ambient lookup channel, so the shell and everything it runs
inherit it, and the unnarrowed SYSTEM channel is closed. The whole sequence
is documented in `docs/service-discovery-model.md` section 7, and su, sshd
and cron follow the same shape: see
[Sessions: login, su, ssh and cron](../compat/sessions.md).

On success login records at debug level, and on any failure at notice:

```text
login: lookup channel for uid 1001 on fd 3
login: no lookup channel for uid 1001: Connection refused
```

The second line is not an error a user sees. The shell starts either way; a
session without a channel is a FreeBSD session, and plane client libraries in
it fail soft.

## What a booted system looks like

Because the kernel executes each unit's program directly, the plane's
daemons appear under their own names. On a default install, trimmed to the
processes this chapter discussed and with PIDs that will differ on yours:

```text
$ ps -axo pid,uid,comm
  PID   UID COMM
    1     0 capsule
   27     0 switchboard
   41     0 BSDFilesystem
   42   976 BSDLog
   43     0 BSDAudit
   44     0 BSDAuth
   45     0 BSDCrypto
   46   976 BSDDevice
   47   976 BSDExtension
   48   976 BSDNetwork
   49   976 BSDNotify
   50   976 BSDPower
   51   976 BSDSysctl
   52   976 BSDTime
   53     0 BSDTrace
  312     0 syslogd
  340     0 devd
  501     0 sshd
  520     0 cron
  588     0 getty
```

Uid 976 is the `capability` user from `etc/master.passwd`, home
`/nonexistent`, shell nologin(8); switchboard logs a critical error and
exits if it is missing or altered. The six root providers run as root
because their manifests say `user = "root"`, which each provider chapter
justifies by the facility it brokers; root is not consulted for any decision
they make. cron was started by rc and then adopted by switchboard as a
supervised rc unit. BSDNamespace, BSDVM and BSDBluetooth are absent until
first use; `switchboardctl services` lists them alongside the running set.

top(1) shows the same names in its COMMAND column and `capability` in
USERNAME for the ten sandboxed providers, so `top -U capability` isolates
the plane's unprivileged half. pgrep(1) and audit records carry the same
names. procstat(1) reports `mac_capability:service[badge]:state` for each
held capability descriptor, which is the quickest way to see what a
process actually holds.

Two more views complete the picture. `capsulectl status` reports PID 1's
claims and integrity flags over the ADMIN-gated `system.lifecycle`
capability that switchboard exposes and relays to capsule, and
`switchboardctl status` reports the registry and the running set over
`system.switchboard`. Neither needs root; both need a session whose lookup
channel can resolve the name. The rest of the tooling is in
[Tool Reference](../operations/tools.md).

## Plane-free boot

Set `capability_plane="NO"` (also `off` or `0`) at the loader prompt or in
loader.conf(5), and capsule's PID 1 path takes the exit described at the top
of this chapter before any plane state is built:

```text
capsule: capability_plane=NO: handing PID 1 to /sbin/init (plane-free boot)
```

It execs `/sbin/init`, forwarding `-s` if single-user was requested, and the
result is an ordinary FreeBSD boot on the same disk: init runs `/etc/rc`, no
switchboard, no providers, `/dev/mac_capability` unclaimed. The kernel is
still the 5BSD kernel with the plane compiled in; only the supervisor stays
down. This exists for recovery, and for the `/dev/mac_capability` device
test suites, which must open the control device and drive it without a live
switchboard owning it. If the exec of `/sbin/init` fails, capsule falls
through and boots the plane, so PID 1 is never left dead.

## Limits

The rc world is still a monolith: switchboard runs `/etc/rc` as one oneshot
and adopts a curated list afterwards; per-service rc units that would let
switchboard supervise every rc.d daemon individually are not built.
`/Capabilities/Run` is a tmpfs rather than a BSDFilesystem-provisioned
dataset. And the login carry, by design, gives up silently: a user who
expects plane services in their shell and does not have them must look in
the auth log, not at their prompt.

**Status.** The sequence above matches `usr.sbin/capsule/capsule.c`,
`usr.sbin/switchboard/startup.c` and `execute.c`, `usr.bin/login/login.c`
and the provider unit manifests at the head of `dev` on 2026-09-25. The
direct fexecve(2) launch that gives units their own process names landed on
2026-09-24 and was validated in the VM rig with `capmode_interp_test`.
