# Native crunchgen and default rescue dispatcher (2026-11-02)

## Genuine producers, bounded products

`bsd_crunchgen` runs the original native crunchgen with explicit, nonempty
object descriptors for every program. No source directory, Makefile or discovery
command is accepted. The existing static `cwd_exec` runner executes it in its
owned output directory, with an empty PATH, an invalid MAKE command, declared
SDK libc/libsys aliases and DOF disabled before startup. Native and fixture
generation both succeed under that environment. The original tool's incidental
Makefile/cache are declared metadata outputs and are never executed by Bazel.
The config is a native FileWrite, not a generated Make query or build wrapper.

`//rescue/rescue:default_dispatch` uses a source-owned default catalog: the actual
103 original programs, 39 aliases and 592 per-program object descriptors. They
come from the independently generated original rescue configuration/cache;
they are descriptors, not a claim that those application objects have compiled.
The declared guard rejects differing values of its thirteen listed boolean
settings. This is a bounded default catalog, not complete option composition or
an automatic Make-source catalog drift verifier. The full rescue parent option
matrix, including selections not yet exposed by existing native settings, remains
open. `dispatch_metadata` exposes the config/cache/Makefile for inspection only.

The dispatcher object uses the original special policy: no PIE, SSP or debug
information. Its ordinary cc_library disables the existing bsd_ssp and
bsd_debug_info features locally, without changing the generator or dependencies.
No rescue executable, application stubs, install manifest or package is declared
before the actual application variants and complete static link exist.

The existing native crunchgen program declaration also now preserves Make's
PIC macro and exact warning policy. Two compiler outputs are forwarded in the
original crunchgen/crunched_skel order directly to cc_binary. The maintained
mkskel.sh source producer, public target and existing installation ownership
remain intact. No crunchgen C source or CLI is changed.

## Evidence

All evidence is under `/usr/obj/usr/src`; accepted target/output comparisons use
the immutable artifact resolver with receipt/manifest/payload SHA and containment
checks, rather than mutable bazel-bin files.

- `bazel-crunchgen-program-make-reference-r2-20261102`: fresh original Make
  tool/skeleton/program/staging reference after production declarations froze.
- `bazel-rescue-original-generation-control-r1-20261102`: original Make and
  the independently built original crunchgen generate rescue.conf, rescue.mk,
  rescue.cache, rescue.c and its single object. This builds no crunched
  application and performs no rescue link, installation or runtime operation.
- `bazel-rescue-dispatch-native-qualification-r2-20261102`: normal format-5
  frontend, selected posttar SDK, 16 jobs and the established 18 GiB start /
  16 GiB reserve guard. Production generation/compilation and ten native test
  targets pass. The native graph invokes neither Make nor a host shell for
  crunchgen generation; it uses the unchanged declared cwd runner.
- `bazel-rescue-dispatch-elf-review-r1-20261102`: generated rescue.c is
  byte-identical to original Make, including its provenance line. Program/alias
  order and all 592 descriptors agree. The dispatcher and both normal crunchgen
  objects have exact allocated sections, non-debug relocation bytes and nm
  symbols. The dispatcher has no debug sections, matching its original recipe.
  The crunchgen program also matches all allocated sections and passes the
  unchanged maintained ELF program checker: PIE/interpreter, ordered NEEDED,
  versioned imports/exports, RELRO/NOW and no RPATH/textrel/executable stack.
- `bazel-rescue-dispatch-action-review-r2-20261102`: five actual uncached
  production/tool compiler records and 166 consumed header/source occurrences
  are bound to original inputs. Ordered warnings, macros, optimization, PIE and
  SSP policy agree. The two execution-configured tool actions have an observed
  -g0 override; the normal installed program preserves Make's debug policy.
  No execution-tool debug-byte identity is claimed. Both mkskel producer outputs
  match Make exactly; two actual BSDCrunchgen actions bind native tool/link
  digests, declared runtime/config inputs and final generated C payloads.
- `bazel-rescue-dispatch-dependency-control-r1-20261102`: the original
  dispatcher recipe emits no -MD/.depend file. An explicit dependency-only
  control retains its exact preprocessing flags and changes only compiler driver
  mode/output to -M/-MF/-MT. It records 50 consumed source/header occurrences;
  original rescue.c, rescue.o and rescue.o.meta hashes remain unchanged. This is
  distinguished from the original compiler .depend records for the tool objects.
- `bazel-crunchgen-link-review-r1-20261102`: actual executed parameter-file
  digest, original two-object order and compiler-to-link-to-capture hashes agree.
- `bazel-crunchgen-install-review-r1-20261102`: five original Make installation
  records match path/type/owner/group/mode/package/debug tags. Actual debuglink
  CRC, literal manual decompression and runtime allocated payload checks pass.
  Archive envelopes and complete debug-byte identity are not claimed.

The compact log is fully streamed with the original upstream converter and all
189 tool bindings verified before and after. Successful flags/input observations
are actual executed records, not configured-action guesses or rebuild counts.
`bazel-rescue-dispatch-review-drivers-20261102` preserves the review scripts and
source/reference/receipt/report bindings.

## Meaningful native tests and retained rejection

Nine expected-failure analysis tests exercise duplicate programs, C-identifier
collisions, missing object descriptors, duplicate aliases, unsafe object paths,
invalid program names, configuration mismatch, unknown alias owners and reserved
entries. A separate runtime wrapper executes the original generated dispatcher
with two side-effect-free print/return stubs. Its six unittest methods cover
program/alias dispatch, hyphenated C identifiers, ordered --list, unknown command,
usage and a hard link made only from a private copy in the test directory.
DOF is disabled before these child processes start. No original rescue program
is executed. Ten actual test-setup spawns and ten XML-generation spawns pass;
there are ten XML wrapper cases, not sixteen XML cases. No skips occur.

The first native attempt was rejected before compilation because the new fixture
referenced unavailable rules_python. It was corrected to the repository's existing
bsd_python_test and declared SDK interpreter; no dependency was downloaded and
no guard weakened. The first input observer's assumption of a dispatcher .depend
file is retained with the explicit original -M control correction.

Existing format-5 target/settings/SDK/test/immutable-artifact support covers
these products and tests. The new rule is exported normally and its test suite
is `//tools/build/bazel/tests/crunchgen:tests`; no frontend C/backend/manual,
staging/signing or publication API changes are required. Full rescue still needs
all application variants, original stub production, relocatable links/crunchide
symbol transforms, complete static library order, final executable/aliases/script
installation, option/architecture/package and safe/guest runtime qualification.
No host install, upgrade, credential operation or reboot was performed. Make
remains production; this is a bounded generator/tool/dispatcher cohort.
