# Plan: plane-native launch, lazy capabilities, and moving past libcasper

## North star

A program launched into the capability plane should:

1. **Never touch the UNIX global namespace** — no `/lib`, `/etc`, `/var/run`, no
   path opens. Its filesystem world is its bundle.
2. **Have its libraries at load** and **find dynamic libraries at runtime**
   (including `dlopen`) from its bundle, by descriptor — not by path.
3. **Not acquire a resource until it needs it** — services open lazily on first
   use over the held lookup channel, never eagerly, never via a per-process
   Casper fork.

The end state retires **libcasper** from the daemons: the plane's own providers
(`system.Network`, `system.Log`, `system.Identity`, …) concentrate the
privilege and serve many clients over channels. Casper's per-process privileged
zygote is the seam we remove.

## The three moments (mental model)

```
LOAD (exec)   map binary + NEEDED libs, fully bound        launcher's job; pre-realm
HANDOFF       deliver lookup channel + lib-dir fd + stdio + identity
cap_enter     realm closes — global namespace gone
REALM         dlopen dev dylibs via lib-dir fd (openat, capmode-ok)
              acquire services lazily over lookup channel on first use
```

Only the **lookup channel** must be held before `cap_enter`; everything else —
including every other service — is acquired after, purely over channels.

## Pivotal constraint (verified in-tree)

Dynamic exec in capmode is blocked today, but **the path-free machinery already
exists** — this is a small enablement, not a new feature:
- `fexecve` execs the binary from a descriptor (`cap_fexecve_rights`, exists).
- `imgp->interpreter_vp` (`sys/sys/imgact.h:96`) lets the activator take the
  interpreter as a **vnode** and skip `namei` entirely — `kern_exec.c:748-749`
  and `:523-528` already honor it. Only `imgact_binmisc.c:746` fills it in today.
- The **only** blocker for normal ELF dynamic binaries is a conservative guard in
  `__elfN(load_file)` (`imgact_elf.c:833-840`): `if (IN_CAPABILITY_MODE) return
  (ECAPMODE);` — whose own `XXXJA` comment says it "can go away once we are
  sufficiently confident that the checks in namei() are correct" — followed by a
  `namei()` on the interpreter's absolute PT_INTERP path.

`rtld`'s `LD_LIBRARY_PATH_FDS` is present and descriptor-relative
(`rtld.c:3745+`), covering `NEEDED` libs and in-capmode `dlopen` once the
interpreter itself is running.

**Decision point.** Two ways to honor "born in the sandbox":

- **(A) near-term, no kernel change):** exec happens **pre-capmode** (rtld loads
  the interpreter + initial `NEEDED` libs), then the program self-sandboxes via
  `service_provider_enter_capability_mode`. Bundle libs resolve via the
  delivered lib-dir fd (`LD_LIBRARY_PATH_FDS`); the only FHS touch at load is the
  trusted interpreter. In-capmode `dlopen` of developer dylibs works from the
  lib-dir fd. This is the standard Capsicum model and needs no `sys/` change.
- **(B) full plane-native, needs approved kernel work):** teach the activator to
  resolve the interpreter from a delivered **directory/anchor descriptor**
  (an `AT_EXECPATH`-style / cap-mode interp fd) so serviced can `cap_enter` then
  `fexecve` dynamic binaries with zero path lookups. Alternatively, **static
  binaries** for the core daemons sidestep the interpreter entirely (no shared
  libs — conflicts with "developers ship dylibs", so reserved for the TCB core).

**DECISION (2026-09-04, Kory): Model B — kernel work up front.** The image
activator will be taught to resolve the ELF interpreter from a delivered
descriptor (cap-mode interp anchor) so serviced can `cap_enter` then `fexecve`
a dynamically-linked binary with zero path lookups — true "never sees UNIX,
even at load." This is an explicitly-approved `sys/` change (sys/ is otherwise
off-limits for capability work). W8 is therefore an active workstream, not a
gated future item. Model A remains the fallback if B proves infeasible.

## Workstreams

### W1 — Launch contract in serviced (near-term, model A)
- serviced opens the unit's application lib directory as an `O_DIRECTORY` fd,
  keeps it past `closefrom`, and sets `LD_LIBRARY_PATH_FDS=<fd>` in the child
  env. Developers drop dylibs in the bundle `lib/`; rtld finds them at load and
  the program can `dlopen` them in the realm — all by descriptor.
- Bundles ship their `.so` set in `lib/`; build daemons with `-z now`
  (BIND_NOW) so no lazy PLT work remains after startup.
- Keep exec pre-capmode; the program self-sandboxes. Document the interpreter
  caveat.

### W2 — Lazy capability acquisition (the "resource only when needed" rule)
- Each capability client lib holds no channel at startup; on the **first call**
  that needs the service it acquires the channel over the lookup channel and
  caches it. Fail-soft on a down provider (retry later), never `err()`.
- Establish the pattern in `liblogcmp`/`libnetworkcmp`; make it the template.

### W3 — Logging substrate (decision + reference conversion)
- Standardize daemon logging on **`system.Log` via `logcmp_emit`**, acquired
  lazily over the lookup channel — **not** Casper `cap_syslog`.
- Reference conversion: replace the `cap_syslog` I added to localnetwork
  (f0ac08e88d2) with a lazy `system.Log` acquire. logd becomes the single
  privileged log concentration point.

### W4 — Provider post-capmode syslog sweep (mechanical)
- Every provider that calls `syslog(3)` after `enter_capability_mode` silently
  drops it. Spot-checked positives: tzfsd, localcrypto, authagentd, bsdnotify,
  auditbrokerd. Give each the W3 channel (or the framework pre-flight, W6).

### W5 — Audit-commit capmode bug (security)
- `auditcmp_submit` fails "Not permitted in capability mode" from sandboxed
  workers → network-op audit records never commit (matches auditbrokerd
  "record not committed"). Likely the adopted audit fd lacks CAP_WRITE/CAP_SEND
  rights or `auditcmp_submit` issues a capmode-disallowed syscall. Probably
  shared across daemons that audit from workers. Fix + regression test.

### W6 — Framework capmode pre-flight (centralization) — DONE (f232179e080)
- `service_capmode_preflight()` (tzset + localtime + strerror) runs at the two
  capmode-entry chokepoints: `service_enter_capability_mode()` (main) and
  `service_worker_protect()` (workers, incl. pre-forked pools). dtrace-verified:
  ZERO errno==94 across the daemons after a resolve. Fleet-wide, one place.
- Remaining pre-flight ideas if needed later: NSS warm-up (getpwuid), BIND_NOW
  as a build default, plane-channel hand-off.

### STATUS 2026-09-05
W5 DONE (audit commits from capmode: libbsm ECAPMODE a8d1af5705b + audit
enabled). W6 DONE (f232179e080). W9 FIRST PASS CLEAN (zero ECAPMODE fleet-wide
on production boot + Network/Log exercise; deeper per-daemon exercise pending).
W12 DONE (aa2a1603678, Config/ delivered as CAPABILITY_CONFIG_FD, localnetwork
converted). auditd enabled in test-rig image (product rc.conf default TBD).
Remaining: W9 exhaustive per-daemon exercise; W10 (3 new capabilities); W11
(waspnest rename — scope TBD, upstream/packaging ripple).

### W9 — Capmode audit AND TEST of ALL daemons (widened W4; firm requirement)
Every provider starts/enters capability mode, so each can silently fail a
capmode-incompatible operation the way auditbrokerd did (audit_submit) — a path
open, NSS/pwd lookup, `/etc` read, sysctl, or a non-capenabled syscall. For
EACH of the 11 daemons: (1) audit — production boot with dtrace
`syscall:::return /errno==ECAPMODE || errno==ENOTCAPABLE/ { @[execname,
probefunc]=count() }` (and capture openat paths) to enumerate every offender;
(2) fix per daemon (pre-open/cache before cap_enter, or route through a plane
capability); (3) TEST — exercise each daemon's real operations on a live plane
and confirm no capmode failures, not just that it boots. Superset of the syslog
sweep. Kory 2026-09-05: this is required, each daemon checked + tested.

### W12 — Deliver Config/ (and run dir) as descriptors, not env-var paths
Today serviced passes the unit/bundle dir as the env var $CAPABILITY_UNIT_DIR
(SERVICE_UNIT_DIR_ENV) and daemons open <unit>/Config/<file> BY PATH before
cap_enter (e.g. localnetwork managed_config_path, networkcmp.c:1340). That path
open only works pre-sandbox — it is the last thing blocking a truly born-in-
sandbox daemon. Extend the launch contract (as W1 did for lib/): serviced opens
the unit's Config/ dir (and the per-instance run dir) as O_DIRECTORY fds and
delivers them (fd numbers via env, like LD_LIBRARY_PATH_FDS), and daemons
openat(configdirfd, name) instead of getenv+open. Then a daemon needs zero path
opens and composes with capmode dynamic exec (rtld -f). The run dir today is
O_CLOEXEC (execute.c:149) and serviced-internal — deliver it too if daemons
need runtime state in capmode. Kory 2026-09-05.

### W11 — Rename the VMM daemon to waspnest
Kory 2026-09-05: rename the VMM daemon to waspnest (aligns with the existing
transitional /usr/sbin/waspnest -> bhyve symlink + man link). Confirm scope:
the bhyve VMM binary vs. vmd (system.VM vsock broker) — clarify which "vmm
daemon" refers to before sweeping. Tree-wide rename with the usual care
(preserve test/historical strings; current names only in public docs).

### W10 — Fill capability-coverage gaps (build-ready designs)
Each is a full provider on the localnetwork template (provider over the lookup
channel; per-client pdfork worker; per-label policy config in the bundle via
service_config_open; libservice capmode pre-flight; ATF pure + plane tests;
bundle with lib/ + Config/; man page). Build sequentially; start with Sysctl.

**system.Sysctl** (retires Casper cap_sysctl): ops GET/SET by MIB name.
Provider resolves name->MIB pre-capmode or via a cached table; enforces a
per-label allow-list (read keys, write keys) from Config/sysctl.conf; performs
sysctl(3) on behalf of the client (sysctl is not fully capmode-usable by name).
Client lib libsysctlcmp: sysctlcmp_get(name,buf,&len)/sysctlcmp_set. Highest
value, simplest — do first.

**system.Identity** (retires Casper cap_pwd/cap_grp): ops PWD_BYNAME/BYUID,
GRP_BYNAME/BYGID, GROUPLIST. Provider does getpwnam/getgrnam etc. (NSS) with
the pre-flight warm, returns fixed-layout records; per-label policy may scope
which lookups are allowed. Overlaps the auth-agent — reuse its plumbing.

**system.Device**: op OPEN(devname, rights) -> delivers a rights-limited fd for
a named /dev node (openat under a held /dev dir fd, cap_rights_limit before
SCM_RIGHTS delivery), exactly the open-descriptor-delivery pattern tzfsd/open
use. Per-label allow-list of device names + max rights. Closes the
device-driver access gap that capmode open("/dev/..") cannot.

Original gap list:
- **system.Sysctl** — brokered sysctl-by-MIB with per-key policy (retires
  Casper cap_sysctl). Highest value: many daemons read sysctls.
- **system.Identity** — getpwnam/getgrnam/getgrouplist over a channel (retires
  Casper cap_pwd/cap_grp; overlaps the auth-agent).
- **system.Device** — open a named /dev node, deliver a rights-limited fd (the
  open-descriptor-delivery pattern); closes the device-driver access gap that
  capmode `open("/dev/…")` cannot.
- Later: system.Time (settimeofday/adjtime), system.Packet (raw/BPF capture).

### W7 — Retire libcasper from daemons
- Once `system.Network`/`Log`/`Identity` cover the needs, drop `cap_net` and
  `cap_syslog` from the daemons and the plane no longer forks Casper zygotes.
- logd stops forwarding via `cap_syslog`; it owns the sink directly (privileged
  concentration point) or forwards while un-sandboxed.

### W8 — SUPERSEDED: no kernel change needed (VM-proven 2026-09-04)
**Experiment result:** a dynamic binary ran in capability mode with ZERO kernel
change. serviced-style helper `cap_enter()`s then `fexecve`s the **static** rtld
in direct-exec mode (`ld-elf.so.1 -f <targetfd>`), and rtld resolves the
target's `NEEDED` libs from a directory descriptor via `LD_LIBRARY_PATH_FDS`.
Because rtld is static, the kernel loads no interpreter for it and the
`imgact_elf.c` `ECAPMODE` guard is never reached. So Model B is delivered
entirely in userland (serviced). The kernel interp-from-descriptor work and the
`XXXJA` guard removal are **not needed** — kept only as an optional future
tidy-up, off the critical path. (Proof: scratchpad `capexec.c`/`hello.c` →
`HELLO-DYNAMIC-OK capmode=1`.)

Original (now-unneeded) kernel plan, retained for reference:
- Machinery already exists (see constraint section): reuse `imgp->interpreter_vp`.
  serviced opens the interpreter via a held dir fd (`openat`, capmode-legal),
  passes the fd into `execve`/`fexecve`; the activator sets `interpreter_vp` from
  it and the existing vnode path runs with zero `namei`. Alternatively lift the
  `XXXJA` `ECAPMODE` guard in `__elfN(load_file)` and make the interpreter
  `namei` descriptor-relative (namei's capmode/beneath checks are what the
  comment defers to). Minimal surface: interpreter resolution only. Then W1's
  lib-dir fd + `LD_LIBRARY_PATH_FDS` covers all `NEEDED` libs + `dlopen`, with no
  FHS touch even at load — serviced truly "born in the sandbox."

## Sequencing
0. **DONE:** VM-proved capmode dynamic exec via rtld `-f <fd>` +
   `LD_LIBRARY_PATH_FDS` — no kernel change (see W8).
1. **W1' (revised, next):** serviced launch path — for a bundle program, open
   the static rtld, the target binary, and the bundle `lib/` dir; deliver
   `LD_LIBRARY_PATH_FDS=<libdirfd>`; `fexecve` rtld `-f <targetfd>` (optionally
   after the child `cap_enter`s). Prove a real daemon (localnetwork) boots from
   its bundle with `/lib` unavailable. Ship bundle `lib/` + `-z now`.
2. W2 lazy service acquire over lookup channel + W3 `system.Log` conversion on
   localnetwork as the reference.
3. W6 (fold the proven pattern into libservice pre-flight).
4. W5 (audit bug — security, standalone; can run in parallel).
5. W4 sweep (mechanical, rides W6).
6. W7 Casper retirement.

## Validation
Per phase: clean production-plane VM boot; census 9/9; the affected daemon's
suite green; for W1, boot with the bundle's `lib/` as the *only* source of its
`.so`s (system `/lib` copies removed/renamed) to prove self-contained load; for
W3/W4, confirm records land in the sink; for W5, confirm audit records commit.

## Risks
- serviced is the security-critical launcher; W1 fd/env/`closefrom` changes need
  careful review (no fd leak into the child, `LD_LIBRARY_PATH_FDS` only honored
  for trusted launches — rtld already refuses it for untrusted/setuid).
- Model A still loads the interpreter from the FHS; "zero UNIX at load" needs
  W8 or static core binaries — call it explicitly, don't imply it.
- Lazy acquisition must stay fail-soft to preserve the no-hard-dependencies
  guarantee.
