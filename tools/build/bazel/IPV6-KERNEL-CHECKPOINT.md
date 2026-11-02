# IPv6 candidate: CTF equivalence gate remains open

**Historical checkpoint, superseded:** see IPV6-KERNEL-QUALIFICATION.md and
CTF-SEMANTIC-CHECK.md for the maintained binary verifier, negative tests and
completed component reviews. The original failure/diagnosis below is retained.

## Current state (2026-11-02)

Twenty-nine selected amd64 GENERIC sys/netinet6 objects have native declarations
in the working tree. They reuse existing kernel helpers and config-derived
option extraction; no kernel C source, runtime policy or new compiler helper
exception was introduced. The existing build-bsd format-5 target/SDK API builds
the candidate without a new C/CLI option. Make remains production/default.
BIP is excluded. This checkpoint is not completed component qualification.

The successful build receipt is under /usr/obj/usr/src in
bazel-kernel-ipv6-amd64-ctf-r1-20261102. It uses all sixteen CPUs and the fresh
bazel-postupgrade-sdk-20261102 SDK. Its target list builds twenty-nine object
groups and tests=[]; no runtime cases ran. Disk reserve monitoring passed.
The separate supported Make meta recipe capture is in
bazel-kernel-ipv6-make-metadata-r1-20261102; all twenty-nine reference object
hashes remained unchanged. They belong to the earlier linked fresh Make kernel,
not a new post-upgrade compilation.

## Failed strict comparison and diagnosis

The immutable artifact review records twenty-nine exact original .text sections
and twenty-eight exact .SUNW_ctf sections. The strict reviewer stops on the
remaining in6_fib_algo.o CTF difference. Its later compiler-input and relocation
checks have not yet run for this cohort; expected Make prerequisite counts must
not be presented as passed native input checks.

Evidence is retained under
/usr/obj/usr/src/bazel-kernel-ipv6-review-r1-20261102, including artifact-review.json
and ctf-diagnosis/{bindings.json,make.stdout,native.stdout,ctf.diff}.
The diagnostic uses the explicitly hashed Make-built ctfdump, not a rewritten
object or a source-specific filename map.

The relative native filename has character-array length 28, also used by a
real gateway-buffer member. Its type is coalesced with that member's array type.
The Make encoding has a nonroot placeholder at type ID 14 and a separate
char[28] type at ID 78. Later IDs and the CTF label boundary shift. The original
CTF blobs remain unequal and both are retained.

A diagnostic text-graph traversal compares all visible type and data/function
symbol roots, preserving property text, reference edges, argument order and
cycles. It found 202 root groups and 536 equivalent type pairs. Native has 536
types; Make has 537, with only its empty nonroot ID-14 placeholder unreachable.
See ctf-diagnosis/type-graph-diagnosis.json and its retained script. This is
supporting diagnosis, not a maintained CTF ABI verifier, negative regression
suite or qualification waiver. Anonymous root groups are compared explicitly,
not treated as unique names.

## Next work

Implement a general maintained CTF semantic verifier from the actual CTF ABI,
with positive ID-renumbering/coalescing and negative type/property/reference
checks. Preserve raw byte comparisons and explicit unreachable-type reports;
do not force parity through a per-file prefix map, ignored failure or modified
Make oracle. Then finish the actual compiler-input/relocation/observability
reviews and qualification documentation before committing the candidate source
batch. Complete kernel aggregation/link/install, other architectures/modules,
world/pkgbase/hardware publication, VM/runtime and controlled performance gates
remain open.

The existing compact-execution-evidence gate also remains important: the WPA
run retains a roughly 9 GiB expanded execution log. Inspect actual required
execution dependencies and cache records; counts or output-root spelling alone
do not diagnose unnecessary rebuilds. Address logging scale through maintained
frontend/decoder integration before full-system qualification.
