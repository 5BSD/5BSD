# Verified Execution

`mac_veriexec` is FreeBSD's fingerprint-based verified-execution policy: a
manifest maps files to hashes, and once enforcement is entered the kernel
refuses to execute, or to open with `O_VERIFY`, any file whose fingerprint
is missing or wrong. 5BSD does not change the policy code. What it changes
is how much rests on it: the capability plane treats a bundle's manifest as
the grant of its authority, and that only holds if the manifest cannot be
altered. This chapter explains the design stance ("declaration is the
grant"), where the plane already reads and executes through veriexec, what
enforcement state does, and the honest status: compiled in, wired up, and
not yet enforcing on any shipped image.

Reference: veriexec(8), veriexec(4), mac_veriexec(4). Design:
`docs/ipc-anointments-design.md` ("Later, separately" and step 1).

## Declaration is the grant

A `Unit.ucl` declares what its unit may hold and do: the anointments in
`holds`, the endpoints it gates with `requires`, the system gates in
`capabilities.system`, the process protections in `protect`. Nothing else
checks those declarations against an allow-list; switchboard reads the file
and acts on it. Installing the bundle is the trust decision (see [Bundles
and Manifests](../plane/bundles-and-manifests.md) and [Anointments and
Principal Policy](../plane/anointments.md)).

That is only sound if the file switchboard reads is the file the publisher
wrote. The intended guarantee is `mac_veriexec` with signed fingerprint
manifests covering each bundle's policy files and programs, verified
against enrolled keys through libsecureboot. Trusting an enrolled key then
means trusting every anointment it declares. The alternative, a hardcoded
list inside switchboard of which programs may hold which gates or names,
was rejected on purpose: it would move policy into code, and it would be a
second, weaker copy of what the signed manifest already says. `usr.sbin/switchboard/execute.c`
states the rule at the point where gate tokens are minted: which gates a
unit receives is its manifest declaration, not an allowlist here.

So the plane is designed as if veriexec will enforce in production, and it
carries no fallback for the case where it does not. The consequence, stated
plainly: on today's images, where veriexec is not enforcing, the manifest is
protected by file ownership and mode alone. Root can edit a `Unit.ucl` and
switchboard will honour the edit at the next load.

## O_VERIFY on every trust-bearing file

Step 1 of the plan is done: the plane opens every file it trusts with
`O_VERIFY`, so that the day enforcement is entered nothing in the plane
needs to change.

| Reader | File | Where |
|---|---|---|
| libcapbundle | `Bundle.ucl`, `Unit.ucl` | `lib/libcapbundle/libcapbundle_parse.c`: opens `O_RDONLY | O_CLOEXEC | O_VERIFY` and feeds libucl the descriptor, since libucl's own open cannot carry the flag |
| libcapbundle | `/Capabilities/Config/principal-policy.ucl` | `lib/libcapbundle/principal_policy.c` |
| switchboard | each unit's program | `usr.sbin/switchboard/execute.c`: `open(m->program, O_EXEC | O_VERIFY)` in the child before the credential drop |

`O_VERIFY` sets the `VVERIFY` access mode, which `vn_open_cred()` passes
to `mac_vnode_check_open` under `options MAC` and then strips. In
`mac_veriexec_check_vp()` a `VVERIFY` open succeeds only when the file's
fingerprint status is valid, or the file is marked `indirect`, or the
caller holds `PRIV_VERIEXEC_NOVERIFY`; otherwise the open fails with
`EAUTH`. When the policy is not in the enforce state its hooks return 0
before looking, so `O_VERIFY` is a silent no-op on an unhardened system.
This is why the change could land ahead of the signing work without
touching behaviour: the plane boots and its full scenario matrix passes
with veriexec absent.

## Exec-time verification of program and interpreter

The second place the kernel checks is `execve(2)`. `exec_check_permissions()`
in `sys/kern/kern_exec.c` calls `mac_vnode_check_exec` for the image, and
the ELF activator in `sys/kern/imgact_elf.c` calls it again for the
interpreter it loads. In 5BSD that second call matters more than it does in
FreeBSD, for a reason that comes from the launch model.

A non-privileged unit is `fexecve(2)`d directly from capability mode: the
launcher holds the program descriptor, and the image activator loads the
brand's own `ld-elf.so.1` for a capability-mode process when
`kern.elf64.capmode_interp` is 1 (see [Capability Mode and the
Born-Sandboxed Launch](capability-mode-and-launch.md)). Before that change
the launcher executed the run-time linker and handed it the program as a
descriptor, so veriexec saw only rtld; the program itself was loaded by fd
and never crossed `mpo_vnode_check_exec`. Now both the program and its
interpreter go through the exec-time check, and the open-time `O_VERIFY`
on the program stays as an earlier, second check. The comment above the
`open()` in `execute.c` calls it belt-and-braces. `O_VERIFY` also closes
the remaining rtld-loaded-by-fd gap for any path that still opens a program
by descriptor.

## What enforcement state does

`mac_veriexec` moves through states, set with `veriexec -z` and read with
`veriexec -i` or `sysctl security.mac.veriexec.state`:

| State | Effect |
|---|---|
| inactive | policy present, no fingerprints loaded, every hook returns 0 |
| `loaded` | set automatically when the first manifest is loaded; still no checking |
| `active` | the policy begins evaluating files; `veriexec -x` can report whether a file is verified |
| `enforce` | `execve(2)` and `O_VERIFY` opens of unverified files fail with `EAUTH`; `no_ptrace` and `trusted` flags block debugger attach; unlink and rename of verified files are refused when `security.mac.veriexec.block_unlink` is set |
| `locked` | no further manifests may be loaded |

Only `enforce` changes an outcome. Every 5BSD-specific consequence in this
chapter, from gate declarations to the exec-time interpreter check, is
inert until that state is entered; the design assumes it will be and adds
nothing that depends on it not being.

A manifest maps relative paths to fingerprints with optional flags:

```
sbin/veriexec              sha256=f22136...c0ff71 no_ptrace trusted
usr/bin/python             sha256=5944d9...876525 indirect
Capabilities/System/Log.cap/Units/bsdlog.unit/Unit.ucl  sha256=...
```

`indirect` marks an executable usable only as an interpreter, `trusted`
marks the process allowed to talk to the veriexec(4) device (and implies
`no_ptrace`), and `label=` attaches a maclabel(7) for other policies to
consume. veriexec(8) verifies a detached OpenPGP or X.509 signature on the
manifest before parsing it, with `-S` enforcing certificate validity, and
`-C` rebases relative paths.

## Hardening in veriexec(8)

5BSD's one change to the tool is in the manifest loader
(`sbin/veriexec/`, commit 45085df89caf). The parser now rejects a
fingerprint whose hex digits are malformed or of the wrong length instead
of passing garbage to the kernel, counts manifest errors, and makes
`veriexec` exit non-zero when any occurred. veriexec(8) records the
important consequence: loading is not transactional, so fingerprints
accepted before the error remain loaded, and an operator must not enable
enforcement after a failed load. `sbin/veriexec/tests/manifest_test.c`
pins the parser behaviour.

## Kernel configuration

GENERIC carries `options MAC_VERIEXEC`, `options MAC_VERIEXEC_SHA256` and
`device mac_veriexec_parser`, so the policy and its SHA-256 fingerprint
parser are static in every 5BSD kernel and no loader.conf(5) line is
needed. The `VVERIFY` path reaches the hook because GENERIC also carries
`options MAC`. Static presence in the inactive state has no runtime cost
beyond the hook registration.

## Honest status

| Item | State |
|---|---|
| policy compiled into GENERIC | done |
| plane reads manifests, principal policy and programs with `O_VERIFY` | done, VM-proven with veriexec absent |
| exec-time check covers program and interpreter for capability-mode units | done (`fexecve(2)` direct launch, `kern.elf64.capmode_interp`) |
| veriexec(8) rejects malformed fingerprints and reports load errors | done, tested |
| keyless integrity baseline for a built image | `release/packages/base-integrity.sh create|check|veriexec` produces an mtree baseline and exports a veriexec manifest for an offline candidate root; opt-in, unsigned |
| build-time signed base manifest covering bundle programs and policy files | not done |
| staged enable knob (off, log-only, enforce) defaulted off so a self-building operator is not locked out | not done |
| enforcement entered on any shipped image | no; the VM test rig does not load or activate veriexec |
| hardcoded allow-list fallback in switchboard or capsule | deliberately absent, and must stay absent |

The middle of that table is the gap. Integrity of a running 5BSD system
today rests on file ownership and the sealed, permission-stripped bundle
tree that switchboard verifies at load, not on fingerprints. A site that
wants verified execution now can build the manifest from
`base-integrity.sh veriexec`, sign it with its own key, load it with
`veriexec -S`, and enter `enforce`; every plane path is ready for that, and
the gate-minting comment in `execute.c` describes exactly what it buys: a
unit's gate set becomes what its verified bundle declares and cannot be
tampered into requesting more. The hardening plan in
`docs/security/5bsd-platform-hardening-plan.md` places this under its
Protected and Locked modes; shipped images are in Compatible mode.

## Relation to the other policies

Veriexec decides whether a file is the file it claims to be. It says
nothing about what the file may do once running; that is the plane's job
([The Authority Model](authority-model.md)), with [mac_abac](mac-abac.md)
and [OES](oes.md) beside it. The dependency runs one way: the plane's
policy files are trustworthy to the extent veriexec vouches for them, and
veriexec needs nothing from the plane. In the deny-wins MAC composition an
`EAUTH` from veriexec is final, and no policy or capability can re-allow an
unverified exec once enforcement is on.
