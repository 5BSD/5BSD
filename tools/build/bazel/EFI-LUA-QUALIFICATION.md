# Private EFI Lua library qualification (2026-11-03)

## Source ownership and policy

`//stand/efi/libluaefi:static_archive` selects the private EFI instance owned by
`stand/liblua`. `library.bzl` holds one ordered list of 31 sources and creates
separate regular and EFI compiler groups. The alias preserves the maintained
component boundary without copying source inventories or reusing regular objects.
Both instances use native rules_cc compilation and the owned-object archive rule;
no Make query, generated Make graph or prebuilt archive enters the native build.

The typed format-5 setting `//tools/build/bazel/config:loader_efi_secureboot`
defaults true, matching the maintained source-option default. It enables the
private instance's LOADER_VERIEXEC and LOADER_VERITY_SUPPORT paths. Explicit
global `veriexec` policy can also enable that private verifier. EFI vector-context
and manifest flags follow the corresponding typed options when the private
verifier is enabled. This does not change the regular instance's flags or enable
crypto in shared BIOS objects. EFI's Wformat and architecture-specific short-wchar
policy are retained; ARM64 and RISC-V keep their previously qualified freestanding
CPU/ABI flags. Separate compile-time checks retain the integer Lua ABI and verify
EFI wchar width on AMD64/ARM64. Contract fixtures remain static-only.

This selects library compiler policy. It is not signature verification, a signed
image, firmware execution, a complete loader or a verified-boot qualification.
The typed settings are explicit qualification inputs; the recorded ARM64/RISC-V
world profiles disable EFI Secure Boot, so their Make comparisons explicitly
enable it for this component. Their world profiles and target SDKs are unchanged.
The selected profiles explicitly disable loader vector-context/manifest options.

## Results

All evidence directories below are under `/usr/obj/usr/src`.

| Architecture | EFI verifier | Frontend qualification | Make reference | Equal allocated members | Symbolic allocated relocations |
| --- | --- | --- | --- | --- | --- |
| amd64 | on | `bazel-efi-lua-amd64-on-r1-20261103` | `bazel-efi-lua-amd64-make-on-r1-20261103` | 31/31 | 4,809 |
| aarch64 | on | `bazel-efi-lua-aarch64-on-r1-20261103` | `bazel-efi-lua-aarch64-make-on-r2-20261103` | 31/31 | 4,587 |
| riscv64 | on | `bazel-efi-lua-riscv64-on-r1-20261103` | `bazel-efi-lua-riscv64-make-on-r2-20261103` | 31/31 | 7,672 |
| amd64 | off | `bazel-efi-lua-amd64-off-r1-20261103` | `bazel-efi-lua-amd64-make-off-r1-20261103` | 31/31 | 4,786 |

Each profile builds both instances through the normal frontend and runs their two
host-artifact targets. Four unittest methods per target cover ordered membership,
loader API/import isolation, per-member ELF machine/ABI, and configured verifier
and verified-source imports. There are eight methods per profile, 32 across these
four profiles; the per-member checks are subtests. Compiler fixtures also check
standalone numeric/FILE ABI, RISC-V soft-float and EFI wchar policy. No foreign
program or firmware executes.

The `bazel-efi-lua-<arch>-<on|off>-review-r1-20261103` reports compare captured
payloads with independently built Make archives: member order, external defined
and undefined symbols, allocated section bytes/type/flags/size/alignment, and
symbolic relocation target/type/value/addend contracts. All four pass. All 124
full object byte comparisons differ; full DWARF/source mapping, debugger and file
byte parity remain open. The archives are INTERNALLIB; the independent references
have no component installation payloads. No fabricated library package entries
were added.

`bazel-efi-lua-action-review-r1-20261103` binds all 124 owned object outputs to
actual noncached compiler actions, their exact private policy/CPU/wchar flags,
standalone configuration headers, actual owned-object archive inputs and captured
final archive hashes. Two successful ABI fixture variants are retained per
profile. Source-definition hashes and comparison/log hashes are recorded. The
upstream compact-log converter and its runtime bindings were verified before and
after each log read.

`bazel-efi-lua-context-isolation-r1-20261103/review.json` compares each shared
archive's captured digest with its preceding qualified standalone capture. All
three shared archives are byte-identical while the private EFI verifier is on.
The regular test also rejects verifier/verified-source imports when not selected.
The disabled amd64 profile verifies the private imports disappear; its artifact
matches an independent disabled-policy Make build.

## Make prerequisites and retained failures

The initial ARM64 isolated Make reference failed because its world object root
had no generated EFI libsa safe headers (limits.h, stdarg.h, etc.). This was not
a reason to synthesize substitute headers or change the source recipes. The
maintained `stand/efi/libsaefi` beforedepend target was run with the original
foreign profiles, verified target compiler/OBJTOP and an explicitly checked
object directory under the normal world root. `bazel-efi-lua-reference-headers-r1-20261103/review.json` records both actual prerequisites. Those recipes create the
same restricted aliases/empty compatibility headers used in a normal build.
They do not compile a complete standalone archive. The failed initial reference
and its logs remain; the fresh foreign references then pass.

Native builds declare their own restricted header view and do not read these
Make-generated prerequisites. The original reference helpers, real source Make
recipes and all 16 logical CPUs were used. The native test policy and independent
Make component overrides are retained as explicit inputs.

## Frontend and remaining work

Existing `build-bsd bazel-test --arch ... --jobs 16 --bazel-inputs ...` format-5
inputs select the alias/archive and both host-artifact tests. Typed build-settings
already pass through the maintained backend; no C frontend option or signing,
staging or publication contract changed. The manual documents the new source
policy and its scope. Make remains production/default. No host installation,
upgrade, reboot or VM run occurred.

The native 64-bit Lua prerequisites are now covered for regular and EFI contexts.
IA32 variants, complete libsa/FDT/Forth archives, entry objects, final EFI
links, firmware runtime and verification failure behavior remain open. Full
world/kernel/modules/pkgbase/hardware publication, reproducible bootstrap, broad
runtime and comparative CPU/memory/disk performance remain separate gates. Archive
code equality and client timing are not whole-system qualification. BIP remains
out of scope.

The later libefi candidate is documented in LIBEFI-QUALIFICATION.md, including
its retained raw assertion-filename differences and independent controls.

The common and EFI FDT archive prerequisites were subsequently qualified in
LOADER-FDT-QUALIFICATION.md. Their firmware runtime and full-loader gates remain
separate from archive/host algorithm checks.
