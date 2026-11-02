# libutil default static consumers (November 2, 2026)

The later [DSO payload qualification](LIBUTIL-DSO-PAYLOAD-QUALIFICATION.md)
corrects native PIC object order and original local-symbol discard. It narrows
the metadata-only DSO scope below while retaining whole/debug/install gates.

## Corrected source contract

Two independent original static consumers exposed distinct defects. An
`expand_number`-only native consumer forced the logincap provider and credential
support through `alwayslink`; the original consumer selected only
`expand_number.o`. An original consumer retaining the `setusercontext` address
selected its implementation but omitted the logincap provider. Neither control
calls `setusercontext` or changes credentials. Original and native rejected
artifacts, extraction reports and link arguments remain preserved.

The original Makefile now enables the existing `DTRACE_STATIC_ANCHOR` mechanism
and a retained, hidden provider reference in `logincap_probes.h`. Native default
compilation uses the same source guard; its provider import permits ordinary
lazy extraction. The component archive retains original 35-member order and now
contains the same required separate anchor. Section-associated experimental mode
keeps WITH_DTRACE and all probes, without the separate-provider pointer. No new
linkage helper or production DOF-reader relaxation is used.

## Independent originals and actual native inputs

A fresh maintained `install-reference.py --make-meta` build produces normal/PIC
objects, archive, DSO and private stage using 16 jobs. All 95 original component
source bindings were rechecked: only three subsequent native test/declaration
files differ; Make compilation sources remain unchanged. The original receipt
was not rebound. Original raw normal/PIC `login_class` controls precede DTrace
object rewriting and preserve full supported compiler recipes.

All 68 actual uncached normal/PIC native compiler actions match owning original
code, allocated sections and nondebug relocation sections. Warning order,
defines, GNU17, optimization/debug/SSP and small-PIC policy pass. All 3,778 original
and 3,778 native consumed input occurrences match actual action digests. The
component archive binds all 35 ordered members to actual producers, including
DTrace output, separate anchor action and archive input. Its 34 C members match
all original allocated sections; all 35 nondebug relocation sections match.
All nine provider DOF descriptors/payloads are accounted for using independently
verified path-key derivations, string offsets and padding. The unchanged reader
checks setusercontext schema, argument mapping, object relocations and NOP site
at offset 560. Archive envelopes, member suffixes and DWARF are not whole-file
parity claims.

Exact actual native link replays, adding only diagnostic extraction output,
reproduce both accepted consumer ELFs byte for byte. Their complete ordered
extraction graphs, including libc edges/reasons, match corrected original Make
after explicit bound directory/archive aliases and conventional object suffixes.
The number consumer selects one libutil member and no probe metadata. The
address-only context consumer selects `_secure_path`, `login_cap`, `login_class`
and the provider; its logincap metadata is present. The old forced-provider and
missing-provider failures remain retained. These two symbol sets do not prove
arbitrary default CcInfo multi-member ordering or complete static-library parity.

## Tests and shared-library scope

The default maintained native profile passes three declared tests: nine archive
contract methods, four static-consumer methods and 43 rescue methods (56 actual
unittest methods). The consumer process environment disables DOF registration
before startup. Safe execution checks number parsing and the retained function
address; no credential change, host configuration change or live tracing runs.

The unchanged shared-library comparator passes libutil.so.10 SONAME, ordered
NEEDED entries, versioned imports/exports, version requirements/definitions and
hardening. Its payload/debug sections differ; full DSO parity remains open.

The historical rescue whole-file regression is explicitly rejected: exactly
220 bytes in eleven DOF UTSNAME version fields differ, matching the historical
and current running-kernel versions. All other bytes are equal. Those DOF
sections have flags zero and lie outside each DOF loadable extent. No production
artifact is rewritten and no comparison normalizes these bytes. Broader DTrace
host provenance and action-cache hermeticity remain open.

The explicit experimental six-target profile also passes its applicable
43-method rescue test. Its archive has 34 C members and metadata embedded only
in login_class, with no separate anchor. The context-address consumer retains
the original logincap schema; the number-only consumer has no probe metadata.
The first local audit incorrectly appended .o to ordinary .o names; the rejected
observer is retained and the corrected explicit suffix check passes. No source
or production artifact changed to satisfy that observer. This is composition
and probe-preservation regression coverage, not experimental library parity.

## Maintained workflow and remaining gates

Existing build-bsd format-5 inputs, SDK validation, compact logging, declared tests
and immutable captures carry the change. The manual documents the bounded test.
No frontend API, generic helper, signing or publication policy changes. Make
remains production/default. No host installation, probe registration, credential
changes or upgrade ran.

Remaining gates include arbitrary CcInfo extraction/order, full DSO/debug/install
and original ATF tests, untraced/options/architectures, experimental whole-library
parity, full rescue/world/packages/hardware, live events, bootstrap/publication
and performance. Historical independent evidence is retained without promoting
it to a current whole-system claim.

## Evidence

All roots are under `/usr/obj/usr/src/`:

- `bazel-libutil-static-consumer-original-controls-r1/r2/r3-20261102`:
  failed initial fixture, original missing-provider baseline and corrected
  originals; sources, Make recipes, extraction graphs and immutable outputs.
- `bazel-libutil-static-anchor-make-reference-r1-20261102` and
  `bazel-libutil-static-anchor-raw-controls-r1-20261102`: fresh independent
  original component and normal/PIC controls.
- `bazel-libutil-static-consumer-baseline-qualification-r1-20261102`,
  `baseline-action-collection-r2-20261102`, `baseline-link-controls-r1-20261102`:
  rejected original native behavior and actual input-bound link replay.
- `bazel-libutil-static-consumer-native-qualification-r1-20261102`,
  `native-action-collection-r1-20261102`, `native-link-controls-r1-20261102`:
  accepted default profile, actual compilers/archives/links and immutable copies.
- `bazel-libutil-static-consumer-compiler-review-r1-20261102`,
  `member-review-r1-20261102`,
  `bazel-libutil-static-anchor-full-dof-review-r1-20261102`: independent policies,
  consumed inputs, member contents and exact provider accounting.
- `bazel-libutil-static-consumer-section-qualification-r1-20261102` and
  `section-action-collection-r1-20261102`: explicit experimental regression,
  actual output/dependency/archive capture and link parameters.
- `bazel-libutil-static-consumer-review-r1-20261102`: extraction, source/test,
  producer, DSO and host-provenance reports; reviewed drivers and final bindings.
