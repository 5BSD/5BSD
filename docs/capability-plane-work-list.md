# Capability plane work list

The live, ranked list of plane work that is decided but not yet built, with
what each item buys and where it plugs in. Records of finished work go in
commit messages and the book; this file holds only the queue. Status words:
**building** (in a working tree), **next**, **later**, **deferred** (decided
against for now, with the reason).

## Attribution: coalition identity and responsibility

**done** (b381a270e2e5 + 773dbd56eb5b; from-scratch build of HEAD validated on the plane 2026-09-27: helper under parent, per-user agent under its owner's session, ssh session join, forty-session churn, audit, boot id, tools). Every coalition carries a
permanent 64-bit id and a set-once responsible-parent edge; the switchboard
records the parent under the management model; login sessions are coalitions
their leaders join; pdfork helpers inherit; kinfo_proc, ps, procstat,
switchboardctl, audit records and OES events expose it. Book:
`book/src/capability/coalitions-and-accounting.md`, "Identity and
responsibility". Open: rc-adopted and oneshot units have no coalition and
therefore no identity (**later**, small); su from a login shell stays in the
login session's coalition (by design, EBUSY on join).

## Imports from Darwin and Plan 9, ranked

1. **Launch constraints** (Darwin, macOS 13) — **done** (2026-09-27,
   VM-validated). A unit's manifest declares who may cause it to exist:
   `launch { responsible = [...] }` over the vocabulary `self`,
   `switchboard`, `session`, `session:uid=<n>`, `bundle`, or a unit label,
   checked at on-demand activation against the responsible party the
   launcher is about to record, before anything is forked. Refusals are
   logged, audited under the on-demand event, traced, and answered to the
   client as an unregistered name. The parser refuses an empty list, a
   label naming a unit this bundle does not have, and a boot-activated unit
   that excludes the switchboard.
2. **Sealed launch record over envfd** (Plan 9 `/env` lineage; Darwin audit
   token) — **next**. See "envfd" below. Gives every unit an attested
   self-description, and retires the environment strings.
3. **Coalition ledgers and pressure bands** (XNU coalitions) — **partly
   done**. Done: a cached footprint sample per coalition
   (`COALITION_OP_LEDGER`, refreshed under pressure and on request, read with
   atomics so a policy needs no lock), and bands with assertion descriptors
   (`COALITION_OP_BAND`, `COALITION_OP_ASSERT`). A band has a floor the
   launcher derives from the management class — CORE is critical, everything
   else maps its declared scheduling band — and assertions raise it: an
   assertion is a descriptor, so it is transferable, revocable, and released
   by the kernel when its holder dies, which is the RunningBoard model
   (item I2) without a daemon reconciling a table. Computing the effective
   band takes no lock, so the kill walk can run where it cannot wait.
   The pass runs on its own taskqueue thread: it walks every coalition, and
   sharing a thread with the per-coalition lifecycle tasks let a walk stall an
   unrelated coalition's teardown, since every close drains those tasks.
   Remaining: a CPU budget and period, racct accounting into a coalition
   subject, work a provider does on a client's behalf charged to the client
   (donation across channel calls, item C2), exhaustion as a coalition
   notification, and the kill walk itself, ordering by band and footprint at
   the top of `vm_pageout_oom()` with the stock path as the fallback. This is
   the substrate a coalition-aware scheduler policy would consume; the
   scheduler itself stays on hold.
4. **Factotum-style key custody** (Plan 9) — **later**. BSDCrypto or BSDAuth
   holds ssh and TLS private keys and runs the handshake on the client's
   behalf; sshd and servers hand over the conversation, never the key.
5. **Transactions for idle exit** (launchd) — **later**, small. A "busy"
   assertion beside the existing idle op so an idle-exit can never reap a unit
   that just accepted work. Check first whether the current protocol already
   closes the race.
6. **Consent keyed by the responsible party** (Darwin TCC) — **later**. Device
   and policy prompts attributed to the responsible label rather than the
   immediate helper; the mechanism exists, this is the consumer.
7. **Plumber-style typed routing** (Plan 9) — **deferred** until there are
   applications to route between; BSDNotify topics cover today's needs.
8. **Per-coalition mount namespaces with union binds** (Plan 9) —
   **deferred**. Containers, BSDNamespace and TrustedZFS anchors cover the
   coarse case; revisit only if capmode path restrictions become the thing
   units fight most.

## envfd: the sealed launch record

Survey (2026-09-26): one producer (switchboard's unit bootstrap at fd 5), one
consumer (libservice), one shape; `ENVFD_CAPMODE_ONLY`, the generation
counter and `EVFILT_ENVFD` have no production user; every other launch-time
datum rides on `char *env[]` strings and bare descriptor numbers.

1. **Extend the unit bootstrap record** (bump `SERVICE_BOOTSTRAP_VERSION`) —
   **next**. Carry the config, unit and resource directory descriptors by role,
   the library directory descriptors, and identity: label, installation id,
   resource owner, coalition id, responsible id. libservice validates each
   descriptor's shape. Remove `CAPABILITY_UNIT_DIR`, `CAPABILITY_CONFIG_FD`,
   `CAPABILITY_DIR_FDS` and `LD_LIBRARY_PATH_FDS` from the environment.
2. **capsule to switchboard bootstrap as a sealed record** — **next**. Retire
   the `SWITCHBOARD_*` environment (bundle roots, run dir, settle time,
   test toggles) in favour of one write-once envfd with magic and version, so
   the TCB's own bootstrap is validated and cannot be redirected by whoever
   controls PID 1's environment.
3. **Session record for login, su and sshd** — **later**. uid, domain kind,
   session coalition id and anointment summary, sealed, delivered with the
   lookup channel; `ENVFD_CAPMODE_ONLY` for capmode consumers.
4. **Tooling** — **later**, small. `procstat files` and `fstat` print an
   envfd's name, state and generation instead of a type letter.
5. **Mutable values with notification** — **deferred**: no consumer exists;
   do not invent one.

## Capability-lineage items (from the systems survey)

1. **Revocation through a derivation tree** — **later**. Every minted or
   attenuated endpoint records its parent; revoking a parent invalidates the
   subtree (logout, anointment withdrawal, container teardown, unit
   quarantine, extension unload). Listed as missing in
   `capability-authority-model.md`. The *coarse* half of the logout case is
   **done** (c0c94a4efe3a, 2026-09-27, VM-validated): ending a login session
   gracefully stops the units that existed on its behalf, and a stopped unit
   no longer carries the id of a coalition that is gone. What remains is the
   fine half: capabilities the session handed to *other* coalitions, which
   is what the derivation tree is for.
2. **Quota lending between coalitions** — **later**, after ledgers. A
   coalition lends part of its memory, descriptor or time budget to a child
   and reclaims it on termination; exhaustion becomes local.
3. **Offline reachability verification** — **later**, small. A tool over the
   manifests and policy files that answers which labels can reach which
   capabilities, run in the test program as a CI gate and as the source of the
   book's capability graph.


## Descriptor forms for ambient APIs

The full audit is `descriptor-addressing-ledger.md`. Its ranked queue, in
order: ntp_adjtime perform op; interface descriptor for ifioctl; ktrace on a
procdesc with a tracefile fd; ptrace on a procdesc; rctl rules bound to
coalition, jaildesc and session capabilities; route-table descriptor for
rtsock and netlink; `P_PROCDESC` and `CPU_WHICH_PROCDESC` on the native
syscalls; `SYS_OP_REBOOT` and kexec by fd; swapon by device fd; kenv perform
ops; audit descriptors; mount onto a directory fd; cpuset descriptor; pf
anchor and bpf-on-interface descriptors; thread descriptor for thr_kill2.
The first six are **next**; the rest **later**. Legacy name and id surfaces
(SysV IPC, ksem, shm and mq unlink by name, quotactl, revoke, nfssvc, jail(2))
are denied under a plane rather than given descriptor forms.

## Borrowed from other systems (survey 2026-09-26)

Two surveys, capability/object-capability systems and Unix descendants plus
industrial kernels, judged against the model: authority is a held descriptor,
never uid, path, pid or name. Only items that fit are kept; the skip list at
the end records what was rejected and why so it is not re-proposed. Ratings
are value / effort; status as above.

### Theme A: supervision as a descriptor

| # | From | Feature | Buys 5BSD | Status |
|---|---|---|---|---|
| A0 | XNU memorystatus | memory-pressure notification: the kernel's low-memory event reaches every live coalition as an advisory note, so units drop caches before anything is killed | **done** (c0c94a4efe3a, 2026-09-27, VM-validated): a global coalition list, a taskqueue pass off the page daemon, `COALITION_NOTE_PRESSURE`, and two kernel tests driven by the low-memory debug trigger. The ledger, bands and kill walk remain (theme C) | done, S |
| A1 | systemd FDSTORE | a unit deposits open descriptors with the launcher and gets them back on restart | providers restart without losing listeners, vsock ports, storage handles; `service_fdstore_put/take(3)` keyed by coalition id | next, S-M |
| A2 | Solaris contracts, Zircon exception channels, KeyKOS keepers | a coalition event/fault stream on a descriptor, adoptable by a new holder, with a keeper who may repair and resume before escalation up the responsibility tree | switchboard and per-user agents can restart themselves and re-adopt units; crash recovery becomes a capability decision; audit gets "handled by" | next, M |
| A3 | Windows job objects | nested coalitions with tighten-only limits, kill-on-close of the last holder's descriptor, event port | the responsible party's descriptor is the unit's lifeline; per-user agents cannot exceed their own ceiling | next, M |
| A4 | cgroup v2 freezer/kill | `COALITION_OP_FREEZE/THAW`, atomic kill closing the fork race | pressure bands can suspend an idle tier before killing it; app-nap for agents | next, S |
| A5 | Zircon job policy | kernel coalition policy (no fork/exec, no W^X flips, no new socket, bad handle = kill) that children can only tighten | a parent states a ceiling once instead of auditing every op | later, M |
| A6 | SMF states, QNX HA ladders, sd_notify set | `maintenance`/`degraded` with operator clear, restart-storm parking, escalation ladder in `watchdog{}`, RELOADING/STOPPING/EXTEND_TIMEOUT/MAINPID | operator semantics without a dependency graph | later, S |

### Theme B: descriptors for legacy code

| # | From | Feature | Buys 5BSD | Status |
|---|---|---|---|---|
| B1 | Landlock | native ruleset descriptor built from directory fds + access masks; manifest `paths{}` builds it before exec | descriptor-shaped sandboxing for rc-compat units, shells, editors that still need path lookup; Linuxulator becomes a shim | next, S-M |
| B2 | seccomp user-notify ADDFD | capability-mode trap broker: an ECAPMODE open traps to the responsible agent, which injects a rights-limited fd | unmodified daemons run born-in-capmode; OES AUTH reply gains a substitute-fd result | later, M-L |
| B3 | openat2 RESOLVE_* | `AT_RESOLVE_NO_XDEV/NO_SYMLINKS/IN_ROOT` on the *at() family | delivered directory fds cannot be walked across mounts or through in-tree symlinks | next, S |
| B4 | Fuchsia runners | the right to exec a Linux-branded binary is a held coalition capability | shrinks the freshly expanded Linuxulator surface to coalitions granted the runner | later, M |

### Theme C: attribution and reclamation

| # | From | Feature | Buys 5BSD | Status |
|---|---|---|---|---|
| C1 | KeyKOS space banks, seL4 untyped | providers allocate against a bank descriptor the client presents; destroying a bank reclaims everything allocated from it, across providers | closes the uncapped clones/snapshots finding; container teardown reclaims in providers that outlive the coalition | next, M (pairs with quota lending) |
| C2 | Mach vouchers (bank attribute) | a channel call carries an attribution token; work done under it is charged to the caller's coalition and inherits its band | quotas and bands stop misattributing provider work | later, L (pairs with ledgers) |
| C3 | Mach no-senders, door UNREF, Binder linkToDeath | notify the owner when the last reference to a delivered object is gone, across dups and passes | per-client state freed exactly on time; complements idle-exit transactions | next, S |
| C4 | cgroup PSI | per-coalition stall indicators with poll-able thresholds | a leading input for bands and lending instead of RSS snapshots | later, M |
| C5 | Linux process_mrelease / process_madvise | reclaim on a node descriptor after terminate; reclaim hints to another process | bounded OOM latency after a band kill | later, S |

### Theme D: misuse of descriptors becomes fatal and auditable

| # | From | Feature | Buys 5BSD | Status |
|---|---|---|---|---|
| D1 | Mach port guards, Apple guarded fds | `fguard(2)`: a guarded descriptor kills the process on close/dup/pass by code without the guard; coalition policy "bad fd = kill" | the ABI-skew stack-smash class turns into an immediate, audited crash instead of a silent capability leak | next, S |
| D2 | WASI borrow handles | `SCM_RIGHTS_BORROW`: a descriptor lent for one channel call, invalidated in the callee on return | providers cannot accumulate client capabilities (the clone-accumulation finding) | later, M |
| D3 | Mach send-once, seL4 reply objects | `CAP_ONESHOT`: consumed by first use | mint replies and consent replies become worthless if copied | later, S |
| D4 | OpenVMS ALARM/AUDIT ACEs | `CAP_AUDIT` right: every use of a marked capability emits an audit record with its derivation path | audit-on-use for anointment roots and VM handles without provider opt-in | later, S |
| D5 | NOVA translate, Zircon koid | `cap_same(a, b)`: do two descriptors denote one object | dedupe and identity checks without leaking anything; the storage TCB confused-identity bugs | next, S |
| D6 | FIDL epitaphs | a final reason code written before close, readable after EOF | fail-soft clients distinguish retry from denied from exhausted | later, S |

### Theme E: attenuation and identity that propagate

| # | From | Feature | Buys 5BSD | Status |
|---|---|---|---|---|
| E1 | KeyKOS sensory keys | `CAP_ATTENUATE_RO` on a channel: everything delivered through it is read-only too | one flag replaces per-op audits for read-only views | later, M |
| E2 | seL4 badges, L4Re gate labels | grantor-chosen opaque badge on a derived endpoint, visible to the server on every message | per-client handles without one channel per client; revoke one badge's cone | later, S |
| E3 | Genode label prefixing, Fuchsia monikers | a unit loaded by an agent is named by its responsibility path (`agent.user123/unit`), unforgeably | provider policy and audit by prefix, now that agents load units the switchboard did not author | next, S |
| E4 | Windows restricted tokens | effective rights of a re-delegated capability = holder's ∧ delegate's declared, evaluated at use | formalises the ad hoc BSDAuth re-delegation fix | later, M |
| E5 | QNX procmgr_ability ranges | gate op capabilities parameterised by ranges (uid in [u,u], port in [1024,65535]), lockable | replaces coarse root-vs-not in gate daemons; step toward the capability-sufficient flag | later, M |
| E6 | E membranes | all session grants derive under one node so session end revokes what escaped to other coalitions | policy on top of the derivation tree | later, M |

### Theme F: verify the live system against its description

| # | From | Feature | Buys 5BSD | Status |
|---|---|---|---|---|
| F1 | seL4 CapDL | `capdump(8)`: enumerate every coalition, channel, bank, envfd and delivered fd as a graph; CI diffs it against the manifest-derived graph | drift and leaked capabilities become test failures; input to reachability verification | next, M |
| F2 | KeyKOS factories, EROS constructor | switchboard attests that a spawned helper's initial capability set is within the caller's grants plus declared holes | runtime, per-instance confinement; the offline check's live twin | later, M |
| F3 | systemd-analyze security | manifest linter scoring each unit's remaining ambient surface (capmode, landlock, pin, limits) | keeps drift down cheaply; joins the graph lint | later, S |
| F4 | Singularity contracts, WIT worlds, Cap'n Proto | typed provider protocols with generated bindings, conformance tests and fuzzers; a unit's world lint-checked against the binary | kills the "manifest says X, code speaks Y" class across 13 providers | later, L |

### Theme G: seal the substrate the grants rest on

| # | From | Feature | Buys 5BSD | Status |
|---|---|---|---|---|
| G1 | macOS SSV | sealed boot environment: sign the BE snapshot's root block pointer at build; loader and veriexec verify before mount | "declaration is the grant" gets a sealed root for the system bundle | next, M |
| G2 | OpenBSD pinsyscalls | syscalls only from rtld-registered stub addresses, on for system-bundle units, manifest opt-out | kills syscall gadgets in TCB daemons; rtld branding already exists | next, M |
| G3 | OpenBSD mimmutable | immutable mappings for sealed records, relro and TCB code pages | cheap complement to W^X | later, S |
| G4 | fs-verity | per-file signed digest in TrustedZFS, verified on read, covering data files, kmods and mapped libraries | extends veriexec past exec-time whole-file hashes | later, L |
| G5 | Windows WDAC | veriexec audit mode and signer rules ("anything signed by the pkgbase key"), signed policy | makes "assumed enforcing" deployable | later, M |
| G6 | Linux keyrings | use-only ("logon") keystore entries with expiry; request_key as on-demand custody activation | the smallest borrow that makes factotum custody sound for ZFS encryption keys | later, M |
| G7 | Symbian DLL rule, Apple library constraints | a capmode unit may map only libraries whose veriexec level is at least its own | a low-trust extension library cannot enter a provider through the lib-dir fds | later, S |

### Theme H: introductions

| # | From | Feature | Buys 5BSD | Status |
|---|---|---|---|---|
| H1 | Powerbox, Genode nitpicker SAK | a failed lookup routed to the responsible session as an introduction request answered by anoint interactively, behind a secure-attention sequence on the tty | consent with a trusted path; GUI later | later, M |
| H2 | Fuchsia config capabilities | typed manifest `config:` schema routed as a sealed envfd, with per-field parent mutability | typed config for providers; agents override only what is marked | later, S (after the sealed launch record) |
| H3 | Hurd passive translators, QNX resource managers | activation by namespace traversal: a container directory served by a unit started on first open | FUSE-like providers for users without root or global mounts | deferred, L |
| H4 | L4Re factories | the right to create coalitions/containers as a delegatable capability with a quota | agents create instances without asking the switchboard by name | later, M |
| H5 | Hydra amplification, E sealer/unsealer | provider-sealed opaque handles that only the issuing provider can unseal | cross-provider handoff through untrusted clients without path or id leaks | later, M |

### Second survey (2026-09-26): Inferno, seL4 ecosystem, QNX, Darwin

Verified against the Inferno 4E manuals, the Microkit and sDDF sources, the
QNX 7.1/8.0 references and the XNU sources; only items absent above.

| # | From | Feature | Buys 5BSD | Status |
|---|---|---|---|---|
| I1 | QNX unblock protocol, seL4 MCS timeout faults | CALL lifecycle: a deadline on a call, a cancel notice with the call id delivered to the provider when the caller dies or times out (provider finishes or rolls back, then replies), and a fault raised on the callee's responsible parent when it exceeds its budget serving someone | closes the half-done-transaction hole (tzfsd commit, warden destroy) when a caller is killed; per-request liveness beside the per-unit watchdog | next, M |
| I2 | Darwin RunningBoard | assertion-derived coalition state: the responsible parent holds assertion capabilities on the coalition descriptor; state (active, background, idle, frozen) and band follow from what is held, and dropping them demotes automatically | one rule instead of separate band, idle-exit and freezer knobs; `procstat` shows *why* a unit is alive; decide before building A4 and the ledgers | **band half done** (2026-09-27): `COALITION_OP_ASSERT` mints an assertion descriptor, the effective band is the highest asserted band over the manifest-derived floor, and the kernel releases an assertion when its holder dies. Remaining: idle and frozen as asserted states rather than separate knobs, and a switchboard op so a unit can be handed an assertion on its own coalition without being handed the coalition | S |
| I3 | Inferno `/prog` fd and ns files, QNX `DCMD_PROC_*`, Darwin task-port flavors | inspection on a held procdesc or coalition: the fd table with rights and delivery origin, a replayable namespace, held channels, STOP/RUN/WAITSTOP, an exclusive debugger right, and canonical CONTROL/READ/INSPECT/NAME rights profiles | the live twin of the capability dump; debugging and triage without pid or path | next, M |
| I4 | seL4 Acacia/sdfgen, QNX secpolgenerate | the system bundle as a generator: one program emits unit manifests, policy files, the reachability graph and VM fixtures; learn mode traces a run and reports unused capabilities | hand-edited manifests become lint-checked exceptions; manifests shrink to what is used | next, M (tooling) |
| I5 | Darwin os_activity | a 64-bit activity id on every CALL, inherited by child calls, stamped by BSDLog and BSDAudit | one request (login, auth agent, tzfsd, logd) greppable end to end; correlation, distinct from cost attribution (C2) | next, S-M |
| I6 | Darwin corpses, stackshot/kcdata, tailspin | post-mortem procdesc (CORPSE state with read and inspect rights, memory plus a self-describing record) and a coalition-scoped snapshot op in BSDTrace with delta snapshots and a trace ring | crash reporting and hang triage (who waits on whom across a coalition) without root or core paths | later, M |
| I7 | QNX MsgDeliverEvent, pulses | a trigger-only event capability (mint, trigger, revoke; bound to one knote on the client's kqueue) and an allocation-free kevent class with code, value and band, with a reserved per-channel pool | providers notify without holding client channel ends; notifications that cannot fail under memory pressure; transport for I1 and I9 | later, M |
| I8 | sDDF shared-memory queues, QNX slogger2 | SPSC free/active ring pair over a delivered memfd with ownership tags and a one-queue invariant, channel used only to notify; a ring-backed mode of the Log capability with a lost-records marker | bulk path for log, trace, audit, net and block providers; rings survive a writer crash | later, M |
| I9 | seL4 CancelBadgedSends, QNX `_NTO_CHF_DISCONNECT` | `REVOKE_INSTANCE`: cancel queued and in-flight calls of one minted instance with ECANCELED while the endpoint survives; a "last endpoint of coalition X closed" notice keyed by coalition id | per-holder cleanup beyond no-senders and epitaphs | later, S |
| I10 | QNX priority inheritance, seL4 ppcall rule | lint now: CALL edges form a DAG and the callee's band is at least the caller's; later, lend the caller's band for the duration of a call with a manifest ceiling and revert on reply | bounded priority inversion across providers | lint next, kernel after SCHED_MIC |
| I11 | Inferno `exceptions propagate/notifyleader`, Microkit monitor | manifest `on_member_fault = isolate/notify-leader/propagate`; faults answered by the responsible parent; a zero-dependency monitor unit for parentless units and the switchboard itself | helpers die together and the parent gets one fault; who restarts the switchboard | later, S-M |
| I12 | launchd LaunchEvents, Inferno registry, QNX pathspace | activation on a device match or a topic with the matched fd delivered; do not answer lookups before ready; descriptor-lifetime registry entries with a version watch; prefix ownership and explicit BEFORE/AFTER/OPAQUE shadowing in the registry | device- and event-driven activation; a registry shape the deferred namespace item needs anyway | later, S-M |

Smaller adopts: BSDLog field privacy flags and signpost intervals; manifest
`budget`/`period` defaults mapped to rctl; CALL metadata fields (reply-buffer
length, ABI bit, jail id); a coalition-scoped signer set for code loading
(Inferno `#Σ`). Larger and later: sDDF-style split drivers with an interrupt
descriptor minted by BSDDevice; export of a container view over a held
channel (Inferno export/rstyxd); a file facade over a held channel (Inferno
file2chan); an OES flow-verdict event class (NetworkExtension filters).

Skipped from this pass: Inferno caphash bearer strings and Styx-as-only-wire
(identity by attach name, rights by mode bits), hosted `emu` as a plane
emulator; seL4 untyped/CNode/VSpace, domain scheduler, verified-artifact reuse;
QNX Qnet (authority carried as uid), sandbox, pathtrust, ability lock/inherit;
Darwin ES mute sets (already in OES), XPC code-signing checks, AMFI, SIP,
DriverKit entitlements, kdebug, work intervals, spawn attributes.

### Skip (decided, do not re-propose)

- Bearer authority in user memory: Amoeba check fields, macOS sandbox extensions as path tokens, Cap'n Proto sturdyrefs as bearer refs. A delivered descriptor is strictly better.
- Identity-attached ambient authority: Solaris privileges bits, Linux file capabilities, Windows integrity levels and AppContainer SIDs, VMS rights identifiers, Binder getCallingUid, systemd DynamicUser.
- Things already covered: Linux namespaces and cgroup hierarchies (jails, BSDNamespace, coalitions, racct), fanotify permission events (OES), seL4 notifications and Zircon ports (kqueue), Plan 9 namespaces and srv (persistent namespaces, registry), NetBSD kauth (mac_capability is the secmodel), Fuchsia static routing (the removed `capabilities{}` block).
- Self-declared sandboxes without a descriptor: OpenBSD pledge/unveil (Landlock plus capmode plus pinsyscalls give the same coverage in descriptor form).
- Needs hardware or a different kernel: CHERI sealing and compartments (track CheriBSD), seL4 untyped memory as a memory model, KeyKOS orthogonal persistence, IBM i tagged objects.
- Language or runtime bound: Singularity SIPs, Joe-E taming, Midori.
- Contrary primitives: QNX MsgRead/MsgWrite into client memory, ALPC impersonation, Linux user namespaces, pidfd_getfd gated by ptrace credentials (a `NODE_OP_GET_FD` gated by a held node right is acceptable for forensics only; A1 covers restarts).
- Scheduler policy work: QNX adaptive partitioning, z/OS WLM, Composite tcaps, door thread handoff; belongs to SCHED_MIC, on hold.

## Decided against

- **Per-thread descriptor tables** — deferred (2026-09-26). Sound design
  (replacement table, no fall-through, one-way confine plus per-thread
  capability mode, high allocation base), but no consumer: not a boundary
  against a compromised address space, and the plane's isolation unit is the
  process. Revisit for in-process untrusted code, a Linux CLONE_FILES gap, or
  when revocation work wants descriptor tables as objects.
- **Userspace scheduler** — deferred. The capability systems that have one
  (Composite) have no kernel scheduler; seL4, Genode, Zircon and KeyKOS keep
  policy in the kernel and make time a held capability instead. That is item
  3 above.
