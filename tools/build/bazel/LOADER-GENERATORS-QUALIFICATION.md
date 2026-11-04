# Native loader font and help generation (2026-11-04)

## Source-owned actions

`//stand/efi/loader:console_font` runs the existing Bazel-built
`//usr.bin/vtfontcvt:vtfontcvt` in the execution configuration. It consumes the
actual Terminus BDF and uses Make's compressed-source arguments. Its generated
8x16.c matches the completed AMD64 Make loader reference byte-for-byte.

`help_common` and `help_fdt` run the maintained `stand/common/merge_help.awk`.
Ordered source labels identify single files; a streaming driver feeds their bytes
to AWK without adding separators. The FDT variant retains Make's FDT-before-common
order. This reuses the source algorithm; it does not parse Makefiles at build time
or implement another help parser. Both variants are explicit candidates; final
loader profile dispatch remains to be wired with the entry/link targets.

Tools, runtime files and data are declared action inputs. The converter uses
cfg=exec and native execution libraries, including when the selected target ABI
is ARM64 or RISC-V. The captured converter is ELF64 little-endian AMD64; its
direct/transitive dependencies close through libc.so.7, libsys.so.7 and the
FreeBSD interpreter. The initial diagnostic audit incorrectly expected libsys
as a direct dependency; revision 2 inspects the complete graph. Production
runtime inputs and the program were unchanged by that audit correction.

The final generator library search paths include shared-library directories.
Pure Python source and test-data directories are not added to LD_LIBRARY_PATH.
The help driver keeps memory bounded while streaming and removes partial output
on errors. Source font/converter/AWK algorithms and diagnostics are preserved.
No installed program payload or policy has changed.

## Executed checks and retained evidence

Paths below are under `/usr/obj/usr/src`:

- `bazel-loader-generators-<arch>-r1-20261104`, for amd64, aarch64 and riscv64:
  successful maintained build-bsd format-5 runs using all 16 logical CPUs.
- `bazel-efi-loader-amd64-make-r1-20261104`: original Make component reference.
  The native font and common help match its actual generated files exactly.
- Native `make-output-review.json`: immutable capture/Make output hash bindings.
- Native `action-review-r2`: actual owned generator actions, copied converter,
  native ELF identity and recursive runtime graph. The first failed diagnostic
  assumption remains in `action-review`.
- ARM64 `configured-action-review`: exact recorded-context aquery, matching
  arguments/environment, all current input hashes and unchanged output captures.
  The initial audit expected fresh spawns and correctly failed when they were
  absent; its `action-review-r2` directory is retained. No action was forced to
  rerun to create evidence.
- RISC-V `generator-executed-actions.json` and `configured-action-review`:
  fresh/reused producers identified separately, with execution-log bindings,
  configured arguments/environment and every current input hash verified.
- Each run's `recorded-inputs` retains its exact frontend input JSON and generator
  implementation versions. The initial rule is retained for the native run;
  final rules are exercised by the RISC-V run.
- `bazel-loader-generator-matrix-review-r1-20261104`: all three configurations'
  output and test-result bindings.

All three configurations produce identical font, common-help and FDT-help bytes.
This is three generated artifacts per configuration, not three new programs or
libraries. The converter's installed foreign binaries are not qualified here.

`//tools/build/bazel:loader_help_test` executes seven methods with declared native
SDK AWK/cat controls: common help, FDT-before-common, unterminated fragments,
input preservation, missing sources, AWK failure/partial-output rejection and
empty input rejection. The methods execute once natively. Both foreign profiles
reuse that passing result; they are not reported as 21 executed methods.

## Cache behavior and remaining construction

ARM64 recompiles the two converter objects and links an identical executable;
all three generators and the test then reuse their earlier results. The cache
review matches configured action arguments, the complete environment, every
current file hash (including expanded native runfiles), and captured output
bytes against the actual earlier producer actions.

With the final shared-library search path change, RISC-V executes both help
actions and reuses the font result and test. Its converter compilation is also
reused. These are component-local cache observations; complete world/cache and
CPU/memory/physical-disk-I/O/storage performance qualification remain open.

Next is version generation, followed by native entry objects and final links.
The version action must use the maintained script, skip metadata-only host calls
in reproducible mode, expose its output/tool inputs explicitly, and support
explicit metadata in the other mode. Supply real declared build information;
do not invent user/host values. PE epoch is already explicit in bsd_efi_image and
must come from selected build policy rather than a copied fixture constant.
The original Make loader link still consumes existing SDK archives; close those
inputs before claiming whole-loader parity.

Full loader/runtime/boot, installation/debug, complete world/rescue/cross kernel
and module, reproducible bootstrap/sandbox, pkgbase/hardware/combined repository
and system-wide performance gates remain required. Make stays production/default;
BIP remains excluded. No VM, host installation, upgrade or reboot occurred.
