# HardenedBSD import audit and first ports

Status: initial source audit and first userland ports, 2026-09-24. This is an
engineering ledger, not a claim that 5BSD implements HardenedBSD's security
properties. Kernel feature families below still require implementation and
qualification.

Scope update, 2026-09-24: prioritize compatibility with ordinary BSD and Linux
software. The active selection is now limited to the two existing ports,
independent defensive fixes, and narrowly scoped compiler-hardening trials.
The wider feature triage remains reference material; it is not the active
implementation queue. See the selection and OPNsense comparison below.

## Pinned sources

The [HardenedBSD project](https://hardenedbsd.org/) publishes its current source
at `https://rad.hardenedbsd.org/z2HLHXgL1xevBNQsf8BmQW7MpJmtm.git`.
The audit fetched that repository and the official FreeBSD repository at
`https://git.FreeBSD.org/src.git`, without changing the 5BSD checkout's remotes.

| Role | Revision |
| --- | --- |
| HardenedBSD `hardened/current/master` | `377c16e8de65d1b5885c4aa26e404f37b90aa2ca` |
| FreeBSD baseline merged into that HardenedBSD snapshot | `fc544d3b57f27f1422969fca0002cb2bff30ab17` |
| Official FreeBSD `main` at audit time | `e40c72c823c6502906d4024933f0c119b5ca17cf` |
| 5BSD before these ports | `ce3522c767bbffddaa71e7e8430e79140e4c554d` |

The baseline is the merge base of the fetched HardenedBSD and its FreeBSD
tracking branch. Comparing that baseline to HardenedBSD isolates retained
changes from FreeBSD development. A historical list of unmerged commit IDs
is unsuitable: this repository includes older imported FreeBSD histories,
reverts, and merge resolutions.

The retained delta contains **666 diff entries**, with 21,625 inserted and
5,619 deleted lines under Git's rename detection. For a path-by-path inventory
it is **667 paths**: the rename of `WITHOUT_FREEBSD_UPDATE` to
`WITH_FREEBSD_UPDATE` contributes two paths.

The complete [TSV inventory](hardenedbsd-delta.tsv) compares those paths at all
four pinned revisions, including file modes:

| Comparison | Matches FreeBSD baseline | Matches HardenedBSD | Diverged |
| --- | ---: | ---: | ---: |
| Latest official FreeBSD | 666 | 0 | 1 |
| 5BSD before these ports | 435 | 0 | 232 |

The one upstream divergence is `sys/kern/vfs_mount.c`; the intervening FreeBSD
changes are not the HardenedBSD allocation/error-handling patch there.
**These are whole-file comparisons, not counts of missing security fixes.**
An independently implemented mitigation can be present even where file contents
differ. Conversely, a file matching the baseline can already contain a
mitigation implemented before HardenedBSD's retained changes.

## Feature triage

Paths below refer to the pinned HardenedBSD tree unless qualified as 5BSD.
This classifies the principal feature families; residual individual fixes in
the TSV remain a review queue, not an approved patch series.

| Area / source evidence | State in 5BSD and import decision |
| --- | --- |
| PIE and stack protection (`share/mk/bsd.opts.mk`, `bsd.sys.mk`) | Already present. PIE defaults on for supported 64-bit targets; SSP uses `-fstack-protector-strong`. Do not import another implementation. HardenedBSD's architecture coverage and exceptions differ. |
| RELRO and eager binding (`share/mk/src.opts.mk`) | RELRO and `BIND_NOW` mechanisms already exist upstream; eager binding defaults off. **Ported the default below**, using 5BSD's existing build machinery. |
| Empty-argument exec protection (`sys/kern/kern_exec.c`, `sys/compat/linux/linux_misc.c`) | Native `kern_execve()` already rejects zero arguments; Linux argument copying inserts an empty `argv[0]`. Do not duplicate the check or import HardenedBSD's separate rejection of a NULL environment pointer. |
| ASLR (`sys/hardenedbsd/hbsd_pax_aslr.c`, `sys/kern/imgact_elf.c`, architecture exec code) | FreeBSD ASLR is already present, including 64-bit stack and shared-page randomization. HardenedBSD's implementation, entropy choices, compatibility handling, per-jail state, and PaX controls are not present. Compare these properties individually before adapting any code. |
| NOEXEC / MPROTECT (`sys/hardenedbsd/hbsd_pax_noexec.c`, `sys/vm/vm_map.c`, `vm_mmap.c`) | Native W^X exists, but `kern.elf{32,64}.allow_wx` defaults true. It is not equivalent to HardenedBSD's restrictions on later executable permission changes. Port remaining enforcement through native VM/procctl and 5BSD MAC paths; test JITs, shared aliases, ELF notes, Linux mmap/mprotect and executable stacks. |
| SEGVGUARD (`sys/hardenedbsd/hbsd_pax_segvguard.c`, exec/signal/unlink hooks) | No equivalent crash-rate/exec suspension mechanism identified in 5BSD. Candidate kernel port; needs executable identity, credential/jail scoping, expiry, unlink/replacement, and denial-of-service tests. |
| PaX policy ABI (`sys/sys/pax.h`, `hbsd_pax_common.c`, `hbsd_control_*`, `lib/libhbsdcontrol`, `usr.sbin/hbsdcontrol`) | Absent. Supplies per-process/per-jail and filesystem policy to the other PaX features. Do not import dependent call sites without a complete policy design. Reconcile with 5BSD's capability authority and existing ELF feature notes/procctl controls. |
| Runtime loader hardening and library-order randomization (`libexec/rtld-elf`, `SHLIBRANDOM`) | HardenedBSD-specific changes remain absent: loader environment restrictions, dependency load randomization, PaX aux-vector handling, and stack defaults. Requires paired loader/kernel work and `dlopen`, `LD_PRELOAD`, TLS, exception-unwinding and debugger tests. |
| CFI, SafeStack, LTO and toolchain changes (`share/mk/src.opts.mk`, LLVM/compiler-rt and per-component Makefiles) | HardenedBSD's build integration is absent. This is a toolchain/world qualification project, including component exclusions and ABI compatibility, not a single compiler flag. The separately advertised cross-DSO-CFI branch was not audited. |
| FORTIFY, variable initialization and register clearing (`bsd.sys.mk`, `bsd.prog.mk`, `bsd.lib.mk`, `sys/conf/kern.mk`) | 5BSD has FORTIFY plumbing (default 0), `INIT_ALL` (default none), and `ZEROREGS` (default off). HardenedBSD enables FORTIFY with SSP and has additional defaults/exclusions. Adapt existing knobs and build/test world and kernels before enabling them broadly. |
| Heap initialization and clearing (`sys/kern/kern_malloc.c`, assorted allocation sites) | `M_ZERO`, explicit zeroing APIs and `recallocarray` already exist; HardenedBSD's blanket kernel allocation/free policy does not. Review callers and performance separately. **Ported the isolated jail(8) allocation change below.** |
| Capsicum SHM and ptrace restrictions (`uipc_shm.c`, `sys_process.c`, `hbsd_pax_hardening.c`) | No HardenedBSD policy plumbing. 5BSD already has MAC checks and expanded Linux debugger support, so wholesale replacement would conflict. Anonymous SHM is currently useful to capability applications; HardenedBSD's extra capmode prohibition requires an explicit capability-aware design. |
| Visibility, hardlinks, chroot, TTY, kenv and module restrictions (`kern_prot.c`, `kern_descrip.c`, `tty.c`, `kern_environment.c`, `kern_linker.c`, `kern_module.c`) | Many underlying upstream knobs exist, while HardenedBSD changes defaults or strengthens their mutability and jail scope. 5BSD also has process shields and system gates. Audit each operation against those gates; do not replace them with root-only authorization. |
| PID randomization and boot-latched controls (`kern_fork.c`, `hbsd_pax_hardening.c`, `init_main.c`) | Upstream PID randomization exists; HardenedBSD changes initialization and control policy. Its init-specific assumptions need adaptation to 5BSD's capsule/switchboard boot. |
| Trusted Path Execution (`sys/hardenedbsd/hbsd_grsec_tpe.c`) | Absent as a HardenedBSD mechanism. UID/path trust rules do not directly implement 5BSD's capability model. Coordinate with the [platform hardening plan](5bsd-platform-hardening-plan.md) and executable-verification work. |
| GEOM/devfs, procfs, Linux and bhyve changes | Retained candidates in the TSV; need subsystem review against 5BSD's heavily modified versions before porting. |
| Application/config changes (`less`, SSH, NTP, `uuidgen`, DB APIs, other small fixes) | Retained review queue. Configuration changes and interface removals need compatibility decisions; existence in HardenedBSD does not by itself establish a security defect in 5BSD. |
| Branding, update infrastructure, package keys, installer and release changes | Exclude from the security port series. 5BSD has its own identity and pkgbase/update design; do not import HardenedBSD trust anchors, repositories, or its pkgbase policy. |
| `contrib/hardenedbsd/liblattzfs` | Separate experimental integration candidate; not a substitute for 5BSD's TrustedZFS work. |

## Ports in this change

### Full RELRO by default

Provenance: Shawn Webb's HardenedBSD commits
`acfca02404c14bed928412ac54f7e1998d06612c` (RELRO/BIND_NOW introduction) and
`444d19dca3bd6cc270a3535e03997e1b303b26e7` (default correction), verified
against the retained current `src.opts.mk` default. The mechanism has since
been implemented upstream; the remaining port is the default.

Move `BIND_NOW` into `__DEFAULT_YES_OPTIONS` in `share/mk/bsd.opts.mk`.
Programs and shared libraries use the existing `-znow` and `-zrelro` paths.
`WITHOUT_BIND_NOW` remains available and is documented in `src.conf(5)`.
The matching manual entry was refreshed from the generator's option text;
unrelated generated architecture-list changes were not included.

Eager binding resolves symbols at startup. It may expose unresolved-symbol
problems earlier and changes startup cost; this first pass does not qualify
every base executable or third-party package. Existing installed binaries do
not change until rebuilt and installed.

### Zeroed jail(8) allocations

Provenance: Shawn Webb's HardenedBSD commit
`ff27ee722b55c68f607b0d6b1113e9f9b9dfb9a4`, "HBSD: jail(8): Use safer memory
management APIs". The change is still absent from official FreeBSD main and
the initial 5BSD checkout.

Use `calloc` for `emalloc` and `recallocarray` for `erealloc`; update every
caller with its old and new element counts. New storage is zeroed, and storage
replaced by `recallocarray` is cleared before release. Unlike the original
HardenedBSD call sites, string old sizes include the trailing NUL (`len + 1`),
matching the actual allocated extent. Allocation diagnostics name the actual
failing API. Existing source copyrights and licenses are retained.

This is defensive allocation hygiene, not a claim to fix a demonstrated
exploitable jail escape. Tests cover variable substitution, empty values,
concatenation, nested jail names and growth across allocation sizes without
creating or changing any running jail. The dependency-parent allocation caller
is compiled, but `jail -e` does not exercise `dep_setup()`.

## Validation

On the available amd64 5BSD host, using source-tree make files and empty build
configuration overrides:

- Built `bin/echo`, `lib/libelf`, and `usr.sbin/jail` successfully. The jail
  build disabled DTrace generation for this targeted check.
- Compared the pre-change and post-change `echo` ELF dynamic sections: the
  former lacks `BIND_NOW`; the latter has `BIND_NOW`/`NOW` and `GNU_RELRO`.
  The rebuilt `libelf.so.2` has `BIND_NOW`/`NOW` and `GNU_RELRO` as well.
- Rebuilt `echo` with `WITHOUT_BIND_NOW=yes` and confirmed the dynamic section
  lacks `BIND_NOW`/`NOW`; the rebuilt default `echo` also ran successfully.
- Built the new jail test program and ran both ATF shell cases directly with
  the rebuilt jail first in PATH: both passed. Kyua was unavailable; these
  were direct ATF runs in separate temporary directories.
- Checked the inventory's 667 paths against `git diff --no-renames` and tested
  the generator with baseline and HardenedBSD equality cases.
- `git diff --check` and `tools/build/checkstyle9.pl` passed for this port.
  `mandoc -Tlint` produced the same pre-existing diagnostics as the original
  `src.conf(5)`, with none added by this change.

No kernel, world installation, reboot, or full release qualification is part
of this first batch. The build objects and logs are under
`/tmp/5bsd-hardened-{before,after,optout}*`. The audit repositories are
`/tmp/5bsd-hardened-audit.git` and `/tmp/5bsd-freebsd-current.git`; they use
local object alternates and are temporary, not self-contained archives.

## Reproducing the inventory

Fetch the source repositories into a separate audit repository with the four
commits above available, then run:

```sh
python3 tools/tools/hardenedbsd/audit.py /path/to/audit.git \
    --base fc544d3b57f27f1422969fca0002cb2bff30ab17 \
    --hardened 377c16e8de65d1b5885c4aa26e404f37b90aa2ca \
    --upstream e40c72c823c6502906d4024933f0c119b5ca17cf \
    --target ce3522c767bbffddaa71e7e8430e79140e4c554d \
    > hardenedbsd-delta.tsv
```

The tool reads Git objects only. It emits additions/deletions separately,
without guessing renames or patch equivalence. For the next audit, determine
the new merged FreeBSD baseline before changing the pins. Keep this initial
inventory pinned to the pre-port 5BSD commit and track adaptations in this
ledger until the next snapshot.

## Active selection: compatibility first

The first standalone defensive batch is implemented and documented in
[Defensive ports](hardenedbsd-defensive-ports.md): logger hostname handling,
QLogic allocation failure, and MegaRAID temporary-command allocation/cleanup.

| Selection | Status and limits |
| --- | --- |
| Existing FreeBSD ASLR, PIE, SSP and RELRO | Retain the existing implementations and compatibility controls. No PaX replacement. |
| Full RELRO / BIND_NOW | Keep the current port and its opt-out. Finish world and representative service qualification before release. It is low risk, not a guarantee of universal compatibility. |
| jail(8) zeroed allocations | Keep the current tested port. |
| Independent defensive fixes | Review specific initialization, bounds, allocation and error-handling fixes that preserve APIs and intended behavior. Port with focused tests; no blanket kernel allocation policy. |
| FORTIFY | Next compiler-hardening trial, initially for selected base components. Keep global defaults unchanged until builds and runtime tests support broader use. |
| Automatic local-variable initialization | Later trial in selected userland components, with performance and compiler checks. No global kernel or third-party build default in this scope. |

Defer MPROTECT/NOEXEC policy changes, SEGVGUARD, PaX ASLR replacement, loader
environment restrictions and load-order randomization, CFI/SafeStack/LTO,
register clearing, blanket kernel heap clearing, Trusted Path Execution, and
new blanket SHM/debugger/visibility/module restrictions. These need a separate
compatibility case before returning to the active selection. No new runtime
restriction or compiler default was enabled by this scope update.

## OPNsense comparison

OPNsense announced its move away from HardenedBSD because of interoperability
and maintenance concerns, then moved to FreeBSD 13 with 22.1 in January 2022:
[project announcement](https://forum.opnsense.org/index.php?topic=22761.0),
[22.1 release notes](https://wiki.opnsense.org/releases/CE_22.1.html).
Its historical use of HardenedBSD is not evidence that modern OPNsense deploys
the complete PaX feature set.

Inspected OPNsense `src` branch `stable/26.7` at
`736f5a1e9142f6b73a7a2a23c2d74dc24e5e6ecb` and `tools` at
`64c6fc6e320d905cb20ae455a55ee9ea115a7e1e` on 2026-09-24. These are source/build
defaults, not an inspection of every installed package or appliance setting.

| Feature | OPNsense source/build defaults inspected |
| --- | --- |
| SSP | Enabled, using `-fstack-protector-strong`. |
| PIE | Enabled for amd64. |
| ASLR | FreeBSD implementation; 64-bit PIE and non-PIE randomization default on. |
| RELRO | Enabled. |
| BIND_NOW | Default off. Our full-RELRO port goes beyond this default. |
| FORTIFY | Default 0. |
| Automatic variable initialization | Default `none`. |
| Register clearing | Default off. |
| W^X | `allow_wx` source default true; this is not HardenedBSD MPROTECT policy. |

Evidence: pinned
[build options](https://github.com/opnsense/src/blob/736f5a1e9142f6b73a7a2a23c2d74dc24e5e6ecb/share/mk/bsd.opts.mk),
[compiler flags](https://github.com/opnsense/src/blob/736f5a1e9142f6b73a7a2a23c2d74dc24e5e6ecb/share/mk/bsd.sys.mk),
[ELF loader](https://github.com/opnsense/src/blob/736f5a1e9142f6b73a7a2a23c2d74dc24e5e6ecb/sys/kern/imgact_elf.c),
and [26.7 build configuration](https://github.com/opnsense/tools/tree/64c6fc6e320d905cb20ae455a55ee9ea115a7e1e/config/26.7).
The inspected tools tree contained no overrides enabling BIND_NOW, FORTIFY,
INIT_ALL, ZEROREGS, CFI or SafeStack. This does not establish the hardening
flags of each individual port/package.

OPNsense also documents stricter hardlink ownership checks, restrictions on
unprivileged debugging, process visibility and kernel-message access, random
IPv4 IDs, and speculative-execution mitigations:
[system hardening documentation](https://docs.opnsense.org/troubleshooting/hardening.html).
Those appliance defaults are not automatically appropriate for a general
purpose development system. In particular, copying its debugger restrictions
would conflict with the compatibility priority here.
