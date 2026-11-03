# Native EFI conversion action (2026-11-03)

## Implementation and boundaries

`bsd_efi_image.bzl` declares the ELF-to-EFI transformation as a Bazel action.
The caller supplies the ELF input, output format, ordered section selection,
unsigned PE timestamp, and converter runtime. The action uses execution-configured
`llvm-nm`, source-built `//usr.bin/elfcopy:elfcopy`, and the declared SDK Python.
Every executable, script and runtime file is an action input. Each subprocess
gets its own explicitly selected runtime, without inherited host loader paths.
No Make recipe executes inside the action.

The timestamp is a required decimal string so the unsigned PE range extends
beyond 2038. The action does not invent an epoch or select platform sections.
The caller must retain the selected architecture/interpreter policy. In
particular, the loader recipe adds command/interpreter linker sets, and ARM64
and RISC-V use their embedded PE headers with a binary section copy. The
current fixture exercises x86-64 PE conversion and binary section copying;
it does not establish foreign EFI correctness.

`efi_image.py` rejects input/output aliasing, invalid timestamps and strong
undefined symbols. Both ordinary and dynamic symbol tables are inspected, so
stripping the ordinary table cannot conceal dynamic imports. Undefined weak
symbols remain allowed. A rejected symbol check removes stale output before
failing. Successful images are produced by elfcopy, not reconstructed in Python.

This is one prerequisite for complete native EFI builds. It does not compile
standalone archives, firmware entry code or a complete loader. It does not
sign an image, test Secure Boot, verify boot policy or protect against root.

## Evidence

The maintained frontend was used with explicit format-5 inputs, the frozen SDK,
16 logical CPUs, and standard `/usr/obj` output locations:

- `/usr/obj/usr/src/bazel-efi-conversion-r1-20261103`: passed; six initial test
  methods executed freshly. Three native actions produced the normal EFI,
  post-2038 EFI and raw-section outputs. Output bytes matched the original
  boot1 nm/elfcopy recipe; checks also covered PE machine/subsystem/timestamps,
  excluded sections, strong unresolved symbols, stale output, in-place conversion
  and invalid timestamps.
- `/usr/obj/usr/src/bazel-efi-conversion-r2-20261103`: analysis failed because an
  empty runtime-only filegroup was expanded in test arguments. No test result is
  claimed from this attempt. The test now uses the SDK's nonempty strip-input
  group and separates the executable from its runtime files.
- `/usr/obj/usr/src/bazel-efi-conversion-r3-20261103`: passed; all seven
  test methods executed freshly, including the stripped dynamic-import rejection.
  The maintained frontend receipt and captured test report record success.
  `efi-action-review.json` records three actual, noncached BSDEfiImage actions
  from the compact execution log, their declared converter tools, section/epoch
  arguments and input hashes matching the current helper. The upstream log
  converter and its recorded runtime bindings were verified before and after use.
- `/usr/obj/usr/src/bazel-efi-real-inputs-review-r1-20261103/review.json`: the
  original Make recipe and the new helper produce identical bytes for existing
  Make-built boot1 and Lua loader ELF inputs: 160,256 and 783,872 bytes. The
  review records tool, script, recipe and input hashes, exact commands and output
  hashes. The Lua comparison includes its additional linker-set sections.
  This proves conversion compatibility on those inputs, not native loader builds.

The independent comparison invokes elfcopy directly with the original section
recipe. PE fields are also inspected independently of the adapter. The negative
fixture has a real unresolved firmware symbol; the stripped regression removes
its ordinary symbol table and checks the remaining dynamic import is rejected.
These are mechanism tests, not substitutes for compiling and booting real loaders.

Disk guards record available space and refuse to cross the configured reserve.
Client `/usr/bin/time` measurements do not establish JVM/worker peak memory or
whole-system performance. CPU, memory, disk I/O, incremental/cache and complete
world/kernel/package performance gates remain open.

## Frontend integration and next work

The normal `build-bsd bazel-test --bazel-inputs ... --jobs ...` interface already
selects the native test label and captures results through maintained backends.
No frontend C option, signing/publication contract or manual interface changed.
The maintained backend produced the recorded receipts; no replacement build
frontend was introduced. Make remains the production/default backend.

Next implement the actual selected standalone and EFI archives with declared
header/generated-source dependencies, boot-specific verification options and
architecture compiler contexts. Link the real boot1/gptboot/loader variants with
their entry objects, scripts and interpreter archives, then connect this rule,
installation metadata and package outputs. Compare those artifacts and exercise
firmware boot separately. Keep BIOS and EFI verifier contexts distinct.
