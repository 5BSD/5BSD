# Authority lifecycle control ABI: moving PID 1 off the signal interface

Companion to `authority-init-todo.md` (Phase 9) and `freebsd-init-behavior-audit.md`
(section 14, the signal ABI). This records the decision to replace the
traditional PID 1 signal ABI with an authenticated control-socket ABI, and how
that decision is shaped by our two-daemon architecture rather than launchd's
single-process one.

## Why move off signals

Stock init is administered by sending UNIX signals to PID 1 (SIGINT=reboot,
SIGUSR1=halt, SIGTERM=single-user, SIGHUP=rescan ttys, ...). That is:

- **unauthenticated beyond uid** — any process that can signal PID 1 can
  reboot the machine; there is no capability boundary;
- **untyped** — eight signals encode the entire lifecycle; no payload, no
  reply, no status;
- **in direct conflict with the capability integrity shield** — Authority's
  `CP_SF_SIGNAL` shield exists precisely to stop ambient signalling of a
  protected process, and PID 1 is the most protection-worthy process on the
  system. Keeping the signal ABI forces a hole in the shield (the current
  `getpid()==1` exception in `apply_integrity()`).

macOS/launchd resolved this by never exposing reboot as a signal: `launchctl`
speaks to launchd over an authenticated Mach port. We take the same principle
— an authenticated IPC control plane — but implement it in the shape of our
architecture.

## Architecture: two halves, two control planes

launchd is one process that is both the PID 1 spine and the service manager,
with one control tool (`launchctl`). We deliberately split those roles:

| Role | Process | Control tool | Owns |
| --- | --- | --- | --- |
| **Spine (lower half)** | `authorityd`/`authority-init` (PID 1) | `authorityctl` | system lifecycle (reboot/halt/single-user/reroot/rescan/catatonia), capability authority, reaping, `/etc/rc`, serviced supervision |
| **Service manager (upper half)** | `serviced` | `servicectl` | per-service start/stop/restart/reload/status, dependency graph, on-demand activation |

This split is *better than launchd's* for the reboot problem specifically:
**system lifecycle authority lives in the spine, below the service manager.**
Reboot does not depend on `serviced` being alive — during shutdown `serviced`
is itself torn down, so its control plane cannot be the one that owns reboot.
In launchd the reboot orchestrator and the service manager are the same
process; here the spine survives the service manager's death, and the reboot
path is correspondingly more robust.

Consequently:

- `shutdown(8)`, `reboot(8)`, `halt(8)` → **authorityd's** control socket. These
  are lifecycle operations; they belong to the spine.
- `servicectl start/stop <svc>` → **serviced's** control socket. Unchanged.

Two tools, split along the trust boundary, instead of one tool spanning it.

## The control ABI

New opcodes on the existing `authorityd` control protocol
(`lib/libauthorityrt/authorityd_ctl.h`; opcodes 7-9 remain reserved):

```
CTL_OP_REBOOT      4    reboot(2) RB_AUTOBOOT   (root)
CTL_OP_HALT        5    RB_HALT                  (root)
CTL_OP_POWEROFF    6    RB_HALT|RB_POWEROFF      (root)
CTL_OP_POWERCYCLE 10    RB_POWERCYCLE            (root)
CTL_OP_SINGLE     11    shutdown to single-user  (root)
CTL_OP_REROOT     12    RB_REROOT                (root)
CTL_OP_RESCAN     13    reread /etc/ttys         (root)  [was SIGHUP]
CTL_OP_CATATONIA  14    stop new login sessions  (root)  [was SIGTSTP]
```

Authorization: root via `getpeereid()` for now (same as `CTL_OP_SHUTDOWN`).
Designed to move to an explicit minted "lifecycle" capability token later —
authenticate the *peer's capability*, never its pathname (per the TODO).

Flow (no async-signal-safety constraints — this runs in the main loop, so it
is strictly safer than the signal handler it replaces):

```
authorityctl / reboot(8) → connect authorityd.sock → CTL_OP_REBOOT
  → control.c: cmd_lifecycle(euid, op) sets od.lifecycle_request, returns
    CTL_ACTION_LIFECYCLE
  → oi_dispatch() translates od.lifecycle_request into requested_transition
    (+ howto/Reboot), exactly as transition_handler() did for signals
  → the multi_user() kqueue loop returns the transition; the existing
    death → death_single → single_user(reboot) path runs unchanged
```

`cmd_lifecycle` rejects the lifecycle opcodes when `getpid() != 1`: an ordinary
`authorityd` daemon is not the system spine and cannot reboot the machine.

## Signals: shield fully, keep a narrow early-boot fallback

Once the control ABI exists, `apply_integrity()` drops the `getpid()==1`
exception and applies the **full** shield (`CP_SF_SIGNAL|SIGKILL|SIGCONT`).
After the engine is up, no process can signal PID 1; lifecycle is the socket.

The signal *handlers* remain installed, but only cover the window **before**
the capability engine starts — early boot, single-user, and `/etc/rc`, during
which the shield is not yet applied and the control socket does not yet exist.
In that window a signal is the only possible mechanism and the attack surface
is minimal. After `establish_authority` brings up the engine, the shield makes
the signal path unreachable and the socket is the sole ABI. Graceful
degradation, not a second permanent interface.

Kernel-internal signals are unaffected by the shield (verified against
`kern_sig.c`: the MAC `proc_check_signal` hook fires only on the `kill(2)`/
`killpg` user path via `p_cansignal`). So `SIGCHLD` reaping, `SIGALRM`
shutdown timeouts, and authorityd's own `pdkill` authority over `serviced`
(procdesc signalling bypasses `p_cansignal`) all keep working under the full
shield.

**Every userland site that signalled PID 1 for lifecycle was converted**, not
just `reboot(8)`/`shutdown(8)`'s common path — otherwise the shield turns those
`kill(1, …)` calls into silent no-ops or fatal `EPERM`s:

- `reboot`/`halt` fast path (`fastboot`/`fasthalt`, `dofast`): the
  `kill(1, SIGTSTP)` that quiesced init is now `CATATONIA` over the socket with
  a SIGTSTP fallback, and made **best-effort/non-fatal** — `reboot(2)` still
  completes if init can't be quiesced (previously `err(1)` aborted the reboot).
- `shutdown -o` single-user (`kill(1, SIGTERM)`): now `CTL_OP_SINGLE` over the
  socket with a SIGTERM fallback.
- Both tools now **fall back to the signal ABI on any non-zero result**
  (socket absent *or* a refusal from a non-PID-1 authorityd that isn't the real
  init), rather than treating a refusal as fatal or silently dropping it.

**Known limitation — `init(8)` telinit (`init 0/1/6/…`, `COMPAT_SYSV_INIT`):**
this SysV-compat path `kill(1, sig)`s PID 1 and is *not* converted, to keep the
fallback `/sbin/init` binary free of any authorityd/socket dependency (it is the
recovery init in `kern.init_path`). Under a shielded authority-init, `init N`
silently no-ops. Use `reboot(8)`/`shutdown(8)`/`halt(8)`/`authorityctl` instead;
telinit under Authority PID 1 is unsupported.

## Emergency reboot when the event loop is wedged

The one robustness cost of removing signals: a wedged authority-init event loop
can no longer be poked by `kill`. Mitigations:

1. **`reboot(2)` direct** — available today. `reboot -q` calls the `reboot(2)`
   syscall directly (reboot.c: `qflag`), touching neither the control socket
   nor init, so any root shell can force an un-orchestrated reboot regardless
   of authority-init's state. This is the manual emergency path.
2. **ddb** `reboot` on the console — the ultimate backstop, always present.
3. **Platform/hypervisor watchdog** — where a deployment has a hardware BMC,
   ILOM, or hypervisor watchdog device, that layer resets a wedged system,
   exactly as Apple's SMC covers a hung launchd and Solaris service-processor
   watchdogs cover a hung svc.startd.

**Decision: authority-init does NOT self-pet a `watchdog(4)`.** Neither launchd
nor illumos SMF has its spine pet a software watchdog; both rely on the layer
below (firmware/SMC/service-processor) plus, in SMF's case, a restartable
brain.  Making PID 1 arm and pet a watchdog would require giving the
multi_user kqueue wait a pat-interval timeout and disarm logic across the
120s-capable shutdown path — real weight in the one process we most want to
keep minimal, to guard a wedged-but-alive PID 1 that a small, mostly-blocked
event loop makes unlikely.  Mitigations 1-3 cover the case.  Keeping PID 1
lean wins.

## Migration order (safe at each step)

1. Add opcodes + `cmd_lifecycle` + `oi_dispatch` translation. Signal ABI still
   present; nothing changes for existing tools yet.
2. Add `authorityctl_lifecycle()` client; teach `reboot`/`shutdown`/`halt` to try
   the socket first and **fall back to the signal ABI** when the socket is
   absent (stock-init systems, and Authority's own pre-engine early-boot window).
3. Only then remove the `CP_SF_SIGNAL` exception and arm the watchdog. Signals
   from other processes are now shielded; the socket is the ABI.
4. Re-validate reboot/halt/single-user/rescan in the VM.

Each step is independently correct; the shield is not closed until the socket
ABI is proven, and the tools keep working on stock init throughout.
