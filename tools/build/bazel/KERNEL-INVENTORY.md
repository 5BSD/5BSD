# Configured kernel product audit

`kernel_inventory.py` is an independent migration audit of a configured Make
kernel. Native builds retain source-owned Bazel declarations; they do not call
this tool or Make to discover compiler inputs during a build.

The audit reads the actual configured identity, architecture, source root,
source lists and final link expression. It preserves SYSTEM_OBJS order and
final-link additions, architecture-specific linker arguments and post-link
commands as data. It does not execute the recorded commands. In particular,
CFILES alone omits custom compile rules and generated interfaces; SYSTEM_OBJS
alone omits the final version object. ARM64 also strips mapping symbols after
linking. None of those operations may disappear from the native kernel graph.

Source files have content hashes. Missing generated outputs remain explicit;
a missing physical source, mismatched configured architecture/source/object
root or unrecognized link expression is an error. Custom products without a
unique source-list binding remain unresolved. A successful query means that
the configured product inventory was read, not that every binding is resolved,
that the configuration is current, or that native artifacts passed.

## Configuration freshness

Generate independent references from the selected current kernel configuration
before using this inventory to claim current-source closure. A configured
Makefile is a snapshot. The old standard amd64 object tree's Makefile dated
2026-10-24, before later configuration and files changes. It selected 2,081
final-link products, while a fresh current-source GENERIC selects 2,466. The
old snapshot remains historical evidence and must not be used as the current
full-kernel baseline. Timestamp comparison exposed the problem; timestamps
alone are not integrity or configuration-provenance proof.

Fresh independent configurations and input/tool hashes are retained under
`/usr/obj/usr/src/bazel-kernel-fresh-config-reference-20261101`. The generator
is the existing Make-built config tool; this is not a fresh independently
bootstrapped toolchain qualification. No kernel was compiled by this step.
The inventory CLI accepts explicit configuration paths and an expected machine
pair; it does not override MACHINE to conceal a wrong configured tree.

## Current evidence (2026-11-01)

Fresh configured inventories are in
`/usr/obj/usr/src/bazel-kernel-product-inventory-r6-20261101`:

| Configuration | Final link products | Unresolved source-list bindings | Missing generated source files |
|---|---:|---:|---:|
| amd64 GENERIC | 2,466 | 13 | 54 |
| ARM64 GENERIC | 2,035 | 20 | 95 |
| RISC-V64 GENERIC | 1,194 | 2 | 62 |

Generated-source counts include helper/interface outputs in GEN_CFILES; they
are not additional final-link product counts. These fresh references are
configured, not compiled. Unresolved products include custom crypto/driver
recipes, VDSO, firmware and final version/dynamic-link objects as applicable.
Their actual recipes and inputs require native reconciliation, not guessed
source names or silently omitted products.

The corrected source-package ownership query analyzes 111 known existing
amd64 native groups and records 286 compiler actions. Three are layout-helper
actions, including two legitimate genoffset variants. Reconciliation against
the fresh Make baseline finds 277 physical source-identity matches, four
generated-name matches and two object-name-only matches; 2,183 final-link
products have no matching action in this inspected graph. This is bounded
configured analysis, not exhaustive Bazel target discovery, compilation or
artifact qualification. See
`/usr/obj/usr/src/bazel-kernel-native-product-reconcile-r2-20261101`.

Fresh option-header audits also show exact unchanged module selections on all
three architectures (729/627/553) and unchanged actual option hashes in the
recent USB, MII and network-support native compiler audits. Evidence is
`bazel-kernel-product-inventory-r6-20261101/fresh-reference-review.json`;
fresh module inventories are in `bazel-fresh-kernel-module-inventory-20261101`,
both under /usr/obj/usr/src. This reconciliation does not turn component
qualification into a complete kernel claim.

## Regression and frontend integration

`//tools/build/bazel:kernel_inventory_test` runs through the normal format-5
build-bsd frontend. It declares the native `//usr.bin/bmake:make` executable
as test data; Bazel execution does not fall back to a host Make binary. The
standalone developer test can use the installed BSD Make. Nine unittest cases
cover actual read-only Make queries, wrong architecture/object roots, relative
configuration source roots, missing physical versus generated inputs,
ambiguous source names, exact link order, final additions and ARM link/strip
steps. The final native test passes in
`/usr/obj/usr/src/bazel-kernel-inventory-test-r3-20261101`. Its retained log
reports nine unittest cases; Bazel XML reports one wrapper case.

The existing frontend C/CLI and format-5 target/test API express this audit
without a new option. No SDK, kernel C source, security policy, production
backend, host installation, module loading or VM state is changed. Evidence
logging, complete execution-platform closure, current full-world/kernel/pkgbase
builds, VM acceptance and controlled CPU/memory/disk/cache qualification remain
open. Make stays the production default; BIP remains excluded.

## Subsequent compiled reference and core checkpoint

After the configuration-only snapshot above, the fresh amd64 GENERIC reference
was successfully compiled and linked by Make with sixteen jobs. Seventy-one
previously unmatched physical core sources now have native amd64 object
qualification. See [the core checkpoint](CORE-KERNEL-QUALIFICATION.md) for the
retained full Make build, native artifacts, compiler/CTF fixes, prerequisites
and precise filename/relocation differences. The earlier 2,183 unmatched count
is an analysis snapshot of its inspected graph, not a newly measured remaining
count after this batch. No full native kernel link or runtime claim follows.

## Current-source refresh checkpoint (2026-11-03)

The fresh independent GENERIC inventory still selects the same ordered 2,462
product names. One of the prior 2,514 bound physical inputs has changed:
sys/kern/init_main.c from the separate CR0.WP startup fix. Current full-kernel
parity must be refreshed; the prior controlled result is not silently rebound.
See [the current refresh record](CURRENT-KERNEL-REFRESH-WORK.md) for actual
configuration/hash evidence, the location-bearing inventory observer correction
and the next full native/Make/aggregate-module checks. This remains inventory
proof only, with missing generated/custom-source bindings explicit.
