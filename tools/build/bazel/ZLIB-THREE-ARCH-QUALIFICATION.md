# zlib library and package family on three userland ABIs

## Scope and result (2026-11-03)

Normal format-5 `build-bsd bazel-test` profiles pass on amd64, ARM64 and
RISC-V with the maintained native/target SDK split. The existing `:z` CcInfo
interface now selects explicit original-order regular and small-PIC archives;
source-owned installation and existing `packages/zlib` targets produce the
three actual selected packages: zlib, zlib-dbg and zlib-dev. No SDK, shared
compiler helper, runtime C, original Make recipe or C frontend changes are
required. Existing frontend artifact capture, package selection and host-test
validation apply; cross artifact tests execute native tools only.

The hash-bound result is
`/usr/obj/usr/src/bazel-zlib-family-package-review-r2-20261103/qualification-summary.json`.
Original references are retained under
`/usr/obj/usr/src/bazel-zlib-original-references-r1-20261103` and independent
original package outputs under
`/usr/obj/usr/src/bazel-zlib-family-make-package-references-r1-20261103`.
Final profiles and immutable action captures use the `bazel-zlib-family-ARCH-`
`native-qualification-r2-20261103` and `action-collection-r2-20261103` roots.

## Production policy and inputs

All 96 regular/PIC production compiler contexts pass exact original policy,
consumed-input identity/digest, allocated payload and runtime relocation checks:
3,648 consumed occurrences. Original source ordering, warning vector,
_LARGEFILE64_SOURCE/HAVE_HIDDEN defines and x86-only UNALIGNED_OK remain explicit.
The existing small-PIC feature preserves original PIC recipes. ARM64's original
Cortex-A53 linker workaround is owner-local. All 96 archive members bind to
actual compiler outputs; regular archive member order and original member
bodies are independently checked. Default static example extraction includes
used compression routines and excludes unrelated zopen/zdopen. PIC DSO inputs
retain original archive order and whole-archive fence, SSP and symbol policy.

The first green profiles were rejected by the input audit: zopen consumed
project header views instead of original SDK zlib.h/zconf.h. The headers happened
to have identical bytes. The final owner-local correction preserves their real
producer identity while other implementation sources consume local headers;
the public consumer header interface remains intact. The rejection and exact
correction are retained, without a general header equivalence waiver.

Three DSO comparisons pass all allocated payloads, ELF architecture/type,
SONAME, ordered NEEDED, versioned imports/exports and hardening. Ten actual
expanded links are retained: six DSO/default static-consumer links across the
ABIs plus four native API-test links. Seven declared test invocations pass:
five native API/artifact tests and one host artifact test per foreign ABI.
Original native upstream example/minigzip tests also pass without changing
production objects. Two immutable native shared-library replay traces bind
execution to the accepted selected DSO; foreign programs were not executed.

## Generated and installed products

Original pkg-config and version-map bytes match. Actual pkg-config execution
is retained from the earlier native run; subsequent cached outputs are bound
to that witness and final output digests. The final version-map AWK action was
cached: original AWK replay on retained preprocessed input reproduces the final
map, and actual DSO linker inputs bind its digest. Fresh AWK execution or
identical cross-configuration action keys are not claimed.

All 33 original installation records match paths, type/link policy, owner,
group, mode, flags and tags, including the explicit debug directory. Three
native debuglink pairs and three original pairs independently pass CRC checks.
Nine actual native packages match nine independent original Make packages for
ABI, identities, dependencies, annotations, ownership, permissions, directory
records and non-ELF payloads. ELF allocated payloads and archive members retain
the accepted production proofs. Native epoch zero and ordinary Make stage
mtimes are checked separately against their declared sources.

## Remaining gates

Package archive byte equality, separate DWARF equality/source lookup and static
archive debug envelopes remain open. This cohort does not establish complete
world/rescue/bootstrap closure, foreign execution, package-manager installation
or solver behavior, repository publication, boot, signing or verified boot.
Libz is a CTF helper dependency; its source and SDK inputs were frozen through
all profile/action captures. Broader consumer rebuild qualification remains
part of the full-world closure.
