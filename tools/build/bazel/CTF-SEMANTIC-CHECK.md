# Standalone CTF semantic inspection

`ctf-artifact-check.py` compares an explicitly selected immutable native capture
with an explicit Make object. It retains both original CTF hashes and the raw
byte-equality result. No object, reference or production source is rewritten.
The scope is type-layout/schema metadata and ELF symbol associations; it is not
complete C ABI/calling-convention, code/data, runtime or whole-system proof.

## Interface

Required arguments are --qualification, --target, --output-suffix,
--make-binary and --output. Capture selection uses qualification_artifacts.py:
the receipt, target, immutable manifest and content hash must match. The report
binds both ELF hashes, both CTF hashes and checker implementation hashes. Output
is created exclusively after success; a failed comparison creates no success
report. A reference change during inspection is an error.

The format definitions are in sys/sys/ctf.h. Symbol filtering/order follows
cddl/contrib/opensolaris/common/ctf/ctf_open.c. The reader parses CTF v2/v3 in
either byte order, compressed or uncompressed, with complete bounds and reference
checks for the supported records. It reads the CTF-linked ELF64 SYMTAB, including
symbol identity/binding/visibility/section/value/size, and associates data and
ordered function return/argument records with their actual ELF symbols.

The initial scope is ordinary ELF64 relocatable standalone containers with zero
or one complete label. Parent/child containers, partial/multiple labels,
extended ELF indices and unsupported type kinds fail explicitly. This is not
an implicit fallback or a claim of every CTF container form. Intrinsic and array
vlen values 0/1 are supported because the maintained CTF library creator and
converter use those encodings. Function padding is record-relative, as required
by the maintained library reader, including v2 tables at unaligned offsets.

## Comparison contract

Type IDs and string offsets belong to each container. The checker compares the
actual properties and ordered references rather than those local numbers.
Joint partition refinement handles cycles without recursion or anonymous-root
backtracking. Compared properties include kind/root/name, sizes, intrinsic
encoding/bit widths, array counts and element/index types, member names and bit
offsets/order, enum names/values, qualifiers/targets and function signatures.

All visible roots and symbol associations are preserved. Nonempty types are
also compared as a multiset of equivalent reference classes, even when not
reachable from a public root. Only completely empty, unreferenced, nonroot
UNKNOWN slots may differ in count. These slots and every unreachable type are
reported explicitly. A referenced UNKNOWN cannot be replaced by void, omitted
metadata or an arbitrary type. The contract compares schema/layout semantics,
not original type-ID identity or graph serialization/sharing.

This handles the independently observed IPv6 encoding difference: native
in6_fib_algo.o coalesces a filename char[28] with a real buffer char[28]; Make
has one unused empty slot and a later identical array. The original raw CTF
blobs remain unequal. No filename-specific option or per-file exemption is used.

## Regression and actual-artifact evidence (2026-11-02)

`//tools/build/bazel:ctf_semantics_test` runs through normal build-bsd format-5
host-test inputs, using the declared SDK Python interpreter/runtime. Twenty-nine
unittest methods pass in
/usr/obj/usr/src/bazel-ctf-semantics-test-r3-20261102. The retained test log reports
29 methods; Bazel XML reports one wrapper case. Fixtures are independently
encoded from the ABI and cover both versions/byte orders/compression modes,
ID renumbering, cyclic references, unused empty slots and extended structures.
Negative cases change fields, offsets, sizes, arrays, integer/float encoding,
enums, pointers, qualifiers, root visibility, function arguments/returns, symbol
identities/associations, labels, bounds/references and ELF/CTF linkage.

A first attempt correctly rejected the artifact-only kernel profile for runnable
host tests. The corrected host profile preserves that frontend restriction;
there is no kernel test-harness bypass. Disk reserve monitoring passed. These
are host unit tests, not VM/runtime or controlled performance qualification.

All 29 actual IPv6 captured objects pass semantic inspection; 28 have identical
CTF bytes. Reports with final implementation hashes are under
/usr/obj/usr/src/bazel-kernel-ipv6-review-r1-20261102/ctf-semantic-r2.
A private real Make-object fixture changes only the CTF member name gw_buf to
gw_bux. Both the reader and CLI reject it; the original hash and original .text
remain unchanged. Evidence is in the same review root's ctf-real-negative-r2.
The initial fixture preparation assumed compression and correctly stopped;
that failed attempt remains separate. Tests and evidence do not establish
complete kernel/link/install, cross builds, system ABI or live tracing behavior.


## Explicit shared-module regression (2026-11-03)

The reader also accepts ordinary ELF64 ET_DYN modules when a caller explicitly
requests allow_shared=True. Its default remains ET_REL-only and ET_EXEC remains
rejected. The native Bazel suite now passes 30 methods, including opt-in and
ELF identity controls. Declared host artifact tests check actual AMD64/ARM64/
RISC-V module full/runtime families and policy-owned named STRUCT associations.
Native passes; the foreign final shared links remain rejected, despite refreshed
objcopy passing the format suite. See CROSS-MODULE-CTF-QUALIFICATION.md for
actual profiles, source/copy controls and still-open producer work.
