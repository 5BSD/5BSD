# Declared original archive inputs for Make references (2026-11-04)

## Maintained reference interface

install-reference.py now accepts --library-inputs for independent original
component archives. This closes comparison links when the selected world SDK
has no corresponding private EFI library. It does not copy archives into the
SDK, invent search-path fallbacks or relax SDK/profile/compiler identity checks.
The ordinary no-input invocation remains supported.

The JSON schema is exactly:

```json
{
  "format": 1,
  "libraries": {
    "LIBSA": {
      "receipt": "/usr/obj/.../receipt.json",
      "receipt_sha256": "<actual receipt SHA-256>",
      "artifact": "objects/usr/src/stand/efi/libsaefi/libsa.a",
      "artifact_sha256": "<actual archive SHA-256>"
    }
  }
}
```

Each key names a LIB-prefixed Make variable. References must have passed for the
selected target architecture, name a component in the selected source tree and
bind the same current compiler content. Archive paths are canonical relative
object-tree files under the corresponding reference component; reference and
archive locations stay under /usr/obj. Unsafe Make/shell path syntax, symlinks
escaping the declared location, digest mismatches, thin archives and linker
scripts are refused. The helper checks each override is effective and appears
in the selected expanded LDADD. Custom direct links instead require --make-meta
and a successful audit of completed original link recipes, outputs and actual
archive operands before installation; see GPT-ISO-BOOT-QUALIFICATION.md. No CC/CFLAGS/LDADD override is supplied by this
API. Caller hashes and receipt paths are explicit inputs, not an authenticated
signing or verified-boot claim.

Input digests are retained in library_reference_inputs and the existing frozen
environment input ledger. Rechecks run before/after every build/install command
and during final verification. Executed commands enter the receipt before the
post-command recheck so corruption failures retain their execution evidence.
The source helpers/modules are included in implementation hashes. Current
reference limitations still apply: these records do not establish a complete
hermetic source/tool-runtime closure or Bazel/runtime parity on their own.

## Executed qualification

Paths below are under /usr/obj/usr/src:

- bazel-efi-loader-aarch64-make-r1-20261104: the initial reference failure is
  retained. Its SDK lacked private EFI Lua/standalone archives and its initial
  configuration also had EFI verification disabled. It is not a successful
  secureboot-profile reference. The RISC-V call in that first sequence did not
  execute after the ARM64 failure.
- bazel-reference-library-inputs-amd64-r1-20261104: maintained frontend runs the
  new validator tests and existing reference-option tests. Captured logs report
  seven and fourteen unittest methods respectively; wrapper XML reports two
  test targets/cases, not 21 XML cases.
- The seven new methods cover exact positive bindings, failed/wrong-ABI/invalid
  receipt format, receipt/archive corruption, variable/path safety, compiler/
  component identity, thin/symlink inputs and late corruption. Their isolated
  schema fixtures are test-only and are never default library inputs.
- bazel-efi-loader-{aarch64,riscv64}-make-closed-r2-20261104: both original Make
  loader references pass with FDT, EFI verification and reproducible version
  generation explicitly selected. Each reference has 48 real object recipes,
  full/debug/symbol/raw-PE outputs and actual installation metadata.
- Each link explicitly binds five independently built original archives: private
  Lua, EFI, common FDT, EFI FDT and private standalone. The actual Make link
  metadata names every supplied artifact exactly once. Library/reference hashes
  remain unchanged, and the SDK's two missing private archives remain absent.
  Proof: bazel-cross-loader-reference-input-review-r1-20261104/review.json.

Both final-source references pass at
bazel-efi-loader-{aarch64,riscv64}-make-closed-final-r3-20261104. Their PE bytes
retain the prior hashes, every declared archive is consumed, and SDK gaps remain
untouched. The final frontend test repeat also passes seven/fourteen methods.
Hash-bound proof: final-review.json in the cross-reference input review. This reference work builds original Make products. Native ARM64/RISC-V
loader entry/link/image targets are still the next implementation step; this is
not evidence that those Bazel targets already exist or boot.

## Workflow and completion gates

The maintained build-bsd format-5 frontend runs the qualification tests and
continues to select Make as the production backend. Its generic target/settings
interface needs no new C switch for this reference-only input. This extends the
maintained reference helper rather than creating an alternate system builder.
Source code, object roots and repositories are not relocated to home directories.

Next carry the actual 48-source inventories, architecture/FDT ABI options, five
library link order and raw image conversion into the source-owned native model.
Then qualify object/input/link/image parity and firmware execution. IA32/other
profiles, full package/shared directory aggregation, world/kernel/module,
reproducible bootstrap/output-query/sandbox/cache, hardware/combined publication
and CPU/memory/disk I/O/storage gates remain open. Make stays production/default;
BIP remains excluded. No host installation, upgrade, reboot or VM occurred here.

## Internal named archive links (2026-11-04)

The vacation original reference exposed LIB<name> prerequisite overrides that
left original LIB<name>DIR-based -L/-l links unchanged. That run fails the audit.
The maintained helper now binds both when the original directory variable exists
and verifies the actual completed search resolves first to the explicit archive.
Earlier archives/shared libraries, default search assumptions, response-file or
mode ambiguity cannot stand in for a binding. Direct original operands remain
supported. Fifteen library-input unit tests and the existing option tests pass;
the real corrected original consumer builds/stages against three freshly bound
original PIE archives. See VACATION-NATIVE-QUALIFICATION.md for bounded evidence.
This changes independent comparison inputs, not production link flags or the
build-bsd backend selection.
