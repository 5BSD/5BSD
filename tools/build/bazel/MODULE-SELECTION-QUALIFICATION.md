# Refreshed amd64 module selection (2026-11-02)

The maintained module_inventory.py completed recursive original Make queries
against the controlled amd64 GENERIC configuration. Parent-exported options
are propagated and each queried architecture is checked. Inputs use /dev/null
for src.conf, make.conf and source environment configuration, with 16 independent
read-only query workers.

- 1,003 source module Makefile directories exist across architectures/options.
- This configuration selects 729 KMOD leaves.
- 245 selected leaves have a local BUILD.bazel; 484 do not.
- 244 use the audited direct amd64_generic_module macro. ZFS has another
  existing build description and needs its own target audit.

These are recursive source-description counts, not native build, dependency,
installation, package or runtime qualification. In particular, missing local
BUILD files need owner/target reconciliation; this audit alone cannot prove
that no source target elsewhere could produce a matching artifact. Existing
cross-architecture component evidence does not close this selected amd64 set.

Evidence: /usr/obj/usr/src/bazel-kernel-module-selection-review-r1-20261102
contains amd64.json (all selected leaves, parent contexts and no query errors)
and source-bindings.json (report hash and selected Makefile/tool hashes).
The tool's existing scope label explicitly limits macro presence to inventory.

Next is source-owned native module closure reconciled against this selection,
including firmware/generated inputs, original flags and exported symbols,
followed by complete kernel-plus-module installation/package aggregation.
A package containing only the recently staged kernel/GDB family must not be
presented as the complete Make kernel-generic package. Original Make names that
package by KERNCONF and includes staged module payloads; debug partitioning also
needs explicit comparison. No compilation, installation or publication is
performed by this audit. Make remains production/default.
