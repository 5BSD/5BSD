# Native AMD64 Forth and simple EFI loaders (2026-11-04)

## Shared source-owned model

//stand/efi/loader_4th and //stand/efi/loader_simp expose entry_objects, full,
symbols, debug, image and install_manifest. They compile the full 58-entry
inventory per interpreter. The existing Lua implementation and these variants
share one maintained source list, one complete object-order model and common
compiler options; the interpreter options are explicit source-owned branches.
No build action parses Makefiles or invokes Make. Native rules_cc compilation
and the shared cc_common firmware link, debug and PE rules retain declared inputs
and ordinary Bazel action caching. Lua target identities remain stable.

Forth selects interp_forth.c, Ficl include context/BF_DICTSIZE, the native private
Ficl archive and the actual version.veriexec dependency chosen by ficl.mk. Simple
selects interp_simple.c, the ordinary version file and no interpreter archive.
Both retain Make's freestanding, verifier, startup, filesystem/network/graphics
source selection and warning policy for the selected AMD64 profile. Forth does
not install common help; simple does. Neither creates the default-loader alias
in this selected default-Lua profile. Other options and foreign/IA32 profiles
remain separate qualifications.

The generated revision strings currently agree across the two version files;
that does not justify substituting dependencies. A dedicated actual-action audit
verifies Forth consumes version.veriexec with its exact digest and produces the
original Make vers.c bytes. Site metadata/reproducible selection and PE time use
the existing typed frontend inputs, without a new clock/identity fallback.

## Retained evidence

Paths below are under /usr/obj/usr/src:

- bazel-efi-loader_{4th,simp}-amd64-make-r1-20261104: independent maintained
  Make references, each with 58 actual object recipes, dependency files,
  selected version input, full/debug/symbol/PE and installation metadata.
- bazel-efi-interpreters-amd64-r1-20261104: maintained frontend builds both
  variants together with Lua, boot1 and gptboot, using all 16 logical CPUs.
- bazel-efi-interpreters-amd64-review-r1-20261104/object-review.json: 112 of
  116 raw entry allocated sections/relocation sets match directly. The remaining
  four are the known disk/gfx_fb assertion filename strings, two per interpreter.
- bazel-efi-interpreters-amd64-closed-reference-r1-20261104: closed original
  links with 58 original entries and explicit original archive inputs. Independent
  original compiler filename controls reproduce the two differing entries per
  interpreter. Raw original objects/archives/PEs are retained unchanged.
- The first Forth final comparison omitted the known private Ficl archive
  filename controls. Its failed helper and diagnosis are preserved in the raw
  review. The separate current Ficl archive review retains 3/15 raw matches and
  twelve expected filename/relocation differences, consistent with
  FICL-CONTEXTS-QUALIFICATION.md. No native artifact was changed to pass the check.
- bazel-efi-interpreter-ficl-filename-controls-r1-20261104: all fifteen original
  private Ficl compiler recipes are reexecuted with only source/generated-source
  macro filename maps. Every allocated section and symbolic relocation matches
  the current native member. Generated softcore input is explicitly captured.
  The fully-controlled Forth reference replaces those members in an isolated
  original archive with identical member order, then runs original link/debug/
  PE recipes. It uses no native object as an original input.
- payload-review.json: both runtime ELF identities, entries, complete program
  headers, allocated section bytes/addresses/metadata and dynamic tables match
  the completed independent controls. PE bytes agree exactly, and debug split
  preservation/debuglink names/CRCs are checked. All default installation
  records match; simple's help matches original bytes and Forth has none.
- bazel-efi-interpreters-amd64-action-review-r1-20261104: all 116 actual compiler
  output chains, 6,227 exact original-consumed source/header digest pairs, two
  complete ordered native final links and both PE output bindings. Interpreter
  BF_DICTSIZE/ABI/verification operands are inspected. No production assertion
  suppression or filename mapping is introduced.
- forth-version-input-review.json in the raw review: exact actual generator
  version.veriexec input/output binding and original version C source comparison.
- bazel-efi-interpreters-amd64-final-r1-20261104: final shared source/order model
  builds successfully with the generated Ficl source captured explicitly. Final
  artifact equality and action reuse are bound by final-repeat-review.json:
  ten variant artifacts agree exactly, existing Lua/boot1/gptboot images retain
  their previous hashes, and no fresh spawn actions execute. This is component
  reuse, without a full-system cache or performance claim.

Full object/DWARF byte equality and source lookup/debugger behavior remain open.
The filename controls explain raw differences; they do not turn the unmodified
original comparisons into full-byte equality or execute firmware.

## Completion scope

The selected 64-bit AMD64 Lua/Forth/simple EFI program constructions now have
native candidates, alongside boot1/gptboot. The IA32 EFI branch, ARM64/RISC-V
entry/link/image profiles, alternate options, complete bootloader package and
shared help/directory contribution aggregation still need qualification.
Common help must be aggregated by its identical declared source/metadata rather
than installing contradictory duplicate entries.

Actual firmware commands, interpreter execution, filesystem/device/error paths,
production trust/key policy, complete world/kernel/module, reproducible bootstrap/
output-query/sandbox/cache, hardware/combined publication and comparative CPU/
memory/disk I/O/storage remain gates. Make stays production/default. BIP is
excluded. No host install, upgrade, reboot or VM was performed here.
