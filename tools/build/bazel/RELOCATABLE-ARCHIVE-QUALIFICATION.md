# Ordered relocatable archive inputs and archive identities

## Implemented scope

`bsd_relocatable_link` accepts ordered archives after its required unique object
inputs, an executable SDK artifact as linker, and optional declared execution
runtime files. Link flags remain explicit. A supplied runtime adds only its
captured library directories to `LD_LIBRARY_PATH`; the action retains a closed
environment with `LC_ALL=C`. Empty archives/runtime preserve existing behavior.
This does not introduce whole-archive behavior for ordinary library dependencies.

The independent ELF archive checker recognizes `.nopic.o` alongside its existing
`.pic.o`, `.pieo` and `.o` variants. This changes source-object identity spelling,
not artifact contents. Both exact member duplicates and collisions after variant
normalization are rejected before member-symbol comparison. Ordered source
identities and all symbol contracts remain strict.

## Performed checks (2026-11-02)

- Final before/after configured queries preserve all four existing csu partial
  link action keys, ordered arguments, input sets, environment, output paths and
  configuration exactly.
- A real native static PAM candidate executed the new path with one registration
  object and 24 ordered module archives. Its action records the selected SDK
  linker, explicit whole-archive flag, 14 captured runtime inputs and their exact
  hashes. The normal maintained format-5 frontend and 16-job disk guard passed.
- Eight real ELF/archive checks passed: identical program/archive, different
  program rejection, `.nopic.o` equivalence, normalized collision rejection,
  missing member rejection, reordered member rejection and changed symbol
  rejection. Only private disposable negative fixtures were modified.

Evidence under `/usr/obj/usr/src/`:

- `bazel-static-pam-csu-query-{before,final}-20261102`
- `bazel-static-pam-relocatable-helper-audit-r1-20261102.json`
- `bazel-static-pam-action-audit-r1-20261102/registration-action.json`
- `bazel-static-pam-native-qualification-r3-20261102`
- `bazel-static-pam-checker-tests-r1-20261102.log`

The original strict PAM symbol comparison remains a recorded failure: path-keyed
DTrace aliases differ. Candidate code matches all 56 text sections, but provider,
relocation, final compiler-policy, installation and authentication checks remain
separate gates. This helper checkpoint does not qualify the full PAM product,
shared modules, live authentication, a full system or performance.

The SDK linker is an accepted captured bootstrap tool. Its absolute ELF
interpreter and the wider execution-platform/sandbox closure remain a completion
gate; declaring its DSOs is not proof of a fully hermetic toolchain. Existing
build-bsd explicit format-5 targets support these rules without a new CLI,
backend input or publication policy.
