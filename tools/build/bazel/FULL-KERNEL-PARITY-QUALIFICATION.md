# Complete controlled amd64 kernel parity (2026-11-02)

## Result and corrected defect

All **2,462 actual native link objects** have byte-identical machine code,
allocated section payloads/metadata and CTF bytes against a fresh independent
Make GENERIC build with the same declared filename/configuration/version policy.
The corrected complete native kernel.full and split kernel also match all 56
allocated section contracts, including **55 byte-identical section payloads**,
96,147 non-file loader symbol identities and byte-identical merged CTF. The one
separate payload is the validated GNU SHA-1 build identity: its format/section
metadata is checked, while its value differs with nonallocated debug inputs.
Whole-file byte identity, including debug data, is not claimed.

This comparison found a real defect in the initial raw-link milestone. Passing
the SONAME-less force-dynamic helper as a full Bazel output path caused lld to
record that path in DT_NEEDED; Make records its basename. This changes dynamic
string sizes, relocation addresses and linked instructions despite identical
compiled objects. The old full kernel is explicitly rejected by the maintained
parity test and remains retained as failed parity evidence.

`bsd_kernel_link` now accepts explicit shared-object basenames and supplies each
using lld's ordinary `-l:filename` with its declared search directory. The kernel
owner declares force-dynamic-hack.pico as that shared input. Shared names must be
unique selected products; regular objects retain direct declared paths and the
full object order is preserved. No ELF contents, SONAMEs or test outputs are
rewritten, and there is no staging/copy loop over all objects in the linker.

## Independent controls

The original ordinary Make baseline remains unchanged. Its initial strict audit
already found all 2,462 machine-code payloads exact, no missing CTF sections,
2,456 exact CTF payloads and six differences accepted by the unchanged strict
CTF type-graph comparator. Remaining allocated differences were source filename
strings in 1,182 objects plus the explicit config/version inputs. A preliminary
complete-filename observer binds 1,413 literals but leaves 26 embedded/aliased
expressions unresolved; that partial observer was not used as parity acceptance.

A **fresh complete Make build** in
`/usr/obj/usr/src/bazel-kernel-canonical-make-control-r1-20261102/kernel`
uses the actual native config override input and native explicit version inputs.
Independent config/env/hints/version bodies match native action output hashes.
Only the original Make COPTFLAGS plus these explicit compiler filename controls
are used for diagnostic spelling:

```
-fmacro-prefix-map=/usr/src/=
-fmacro-prefix-map=/usr/src/sys/../=
-fmacro-prefix-map=./=
```

The paths above are measured source-root spellings in this qualification, not
hardcoded production build roots. Native compilation already uses relative
declared paths. These controls change compiler inputs; no observer normalizes
object contents or relocation records. The original Make source/link policies,
all normal/custom/generator recipes, original tools and -j16 remain in use.
2,514 physical input hashes remain stable across the build. The baseline's
normal timestamp/host version and absolute filename outputs are preserved.

## Actual native execution and tests

`bazel-kernel-full-link-native-r4-20261102` completes the corrected native link,
CTF merge and debug split through normal format-5 build-bsd. Immutable captures
are resolved with receipt/manifest/content hash verification. Four actual
executed pipeline records are retained; the response file and all recorded
link input/tool digests are checked. All 2,462 object positions remain equal to
the original Make inventory, including the shared helper's basename slot.

The maintained `elf-kernel-parity-test.py` rejects the old kernel's allocated
runtime/dynamic differences and accepts both corrected full/runtime captures.
It checks every allocated section, separately validates the one GNU build-ID
note, compares all non-file loader symbols, records file symbols, and requires
identical merged CTF. The existing real-kernel debug test also passes the
corrected pairing and all five corruption/mode/name rejection cases.

Evidence roots under `/usr/obj/usr/src`:

- `bazel-kernel-full-object-parity-r1-20261102`: strict ordinary-baseline audit,
  type-graph checks, partial literal observations and actual config/version actions.
- `bazel-kernel-canonical-make-control-r1-20261102`: independent Make build,
  explicit policy/commands, stable input hashes and matching generated bodies.
- `bazel-kernel-full-object-parity-r2-20261102`: all 2,462 strict object matches,
  retained pre-fix kernel rejection and pre-fix final section differences.
- `bazel-kernel-full-link-native-r4-20261102`: corrected production backend build
  receipt, immutable four-artifact capture and original execution log.
- `bazel-kernel-full-link-review-r2-20261102`: accepted full/runtime comparisons,
  actual corrected link/input records and debug checks.

The original Make kernel-install target also ran into a fresh disposable stage
at `bazel-kernel-install-make-reference-r1-20261102`, producing eight files with
recorded root/wheel/0444 metadata and the 0755 GDB helper directory. Its dry run
excludes host bootfile mutation and destructive upgrade branches. This supplies
the next native installation inventory; native installation/pkgbase parity is
not implemented by this cohort.

## Frontend and remaining gates

The existing build-bsd format-5 kernel profile drives the corrected backend;
there is no new frontend C option, manual option or alternate production build
path. Backend rule/owner and maintained parity test changed together. Signing,
verified boot and compromised-root protection are not tested here.

This qualifies controlled compiled/runtime artifact parity for default amd64
GENERIC, not VM behavior or arbitrary configurations. Native installation and
pkgbase integration, module/driver closure, ARM64/RISC-V builds, complete world,
bootstrap, hardware/combined repository publication, VM boot/login/SSH and other
runtime coverage, incremental/cache/sandbox and controlled CPU/memory/disk-I/O
performance qualification remain open. No host installation, upgrade or reboot
occurred. Make remains production/default; BIP remains excluded.
