# Virtual-memory kernel object qualification

## Scope (2026-11-02)

All twenty-four previously unmatched sys/vm physical sources selected by the
fresh amd64 GENERIC inventory now have native built-in object targets. This is
component qualification; complete native kernel aggregation/link/install,
other configurations/architectures, modules and whole-system gates remain open.
No host installation, module loading, network changes or reboot were performed.

Each object declares its source, required option/interface headers and physical
header contexts in the packages owning those files. Existing native kernel
compilation, CTF and offset/vnode generation helpers are reused. The one missing
option extraction, opt_kstack_max_pages.h, comes from the actual selected config
tree. Existing option extraction actions are reused through narrow consumer
views. Native analysis/build actions do not query Make or read audit metadata.
No production C source or runtime policy was changed by this cohort.

The normal format-5 build-bsd bazel-test inputs already express the selected
SDK, kernel target kind, build settings and object targets. No new frontend C
option or backend replacement is needed. The maintained manual is updated with
this cohort and its qualification limits. Make remains production/default.

## Upgrade and SDK baseline

The resumed host is GENERIC-NODEBUG hypertrace-n287589-40ea99e869b4, with sixteen
logical CPUs. The old execution-baseline validation found eight changed host
inputs: bsdtar, libc, libthr, the runtime linker, libutil, libarchive, libcasper
and libcap_fileargs. Frozen SDK contents and recorded kernel configuration/tool
hashes remained unchanged. The rejected validation is retained as
/usr/obj/usr/src/bazel-resume-host-validation-20261102.json.

A new SDK was prepared by the maintained libmd-plan.py and libmd-stage-tools.py
helpers under /usr/obj/usr/src/bazel-postupgrade-sdk-20261102. The normal
explicit SDK input API uses this new receipt; no historical receipt was edited
to conceal changed execution inputs. Preparation commands are retained in
bazel-postupgrade-sdk-preparation-20261102. All 16,812 new recorded input,
snapshot, host dependency and kernel configuration/tool checks passed in
bazel-resume-new-sdk-validation-20261102.json, under /usr/obj/usr/src.
This baseline still reuses explicitly selected Make-built SDK/tool binaries;
it does not establish an independently bootstrapped or hermetic toolchain.

## Evidence and checks

Under /usr/obj/usr/src:

- bazel-kernel-vm-make-metadata-r1-20261102 captures supported Make meta recipes
  for the twenty-four existing objects, with sixteen jobs and filemon disabled.
  All original object hashes stayed unchanged. The reference objects are from
  the earlier successfully linked fresh Make kernel, not a new post-upgrade
  compilation. Source/configuration freshness, actual recipes and physical
  input hashes are checked separately; kernel execution is not qualified here.
- bazel-kernel-vm-amd64-ctf-r1-20261102 contains the successful normal frontend
  build, immutable captures, receipt and actual execution log, using the new
  SDK and sixteen workers. The target profile has tests=[]: no runtime test
  cases were executed by this component build.
- bazel-kernel-vm-review-r1-20261102 contains retained inputs/review scripts,
  original section hashes, compiler input audits, filename/relocation review
  and source-bound observability findings.

All twenty-four original .text sections and all twenty-four .SUNW_ctf sections
match Make byte for byte. Actual successful compiler records and converter
input/output hashes bind the inspected objects to immutable captured outputs.
All twenty-four compiler actions pass ordered warning-vector, macro-definition
and stack-protector checks against their actual Make recipes. The input audit
verifies 3,725 physical prerequisite bindings (316 unique files) and 113
consumed generated bindings, including actual option and vnode interface data.

Twenty-one objects have raw runtime-section differences: thirty diagnostic
filename expansions use relative native versus absolute Make physical-input
names. All 14,468 nondebug relocations compare equally by symbolic target after
accounting for those exact filename spellings/string offsets. Original section
hashes and strings are retained; production objects are never rewritten for
parity. Whole object/debug/symbol/string-table byte identity is not claimed.

Eleven of the unchanged sources contain direct tracing/audit/CTR/lockstat
markers in a bounded scan; thirteen do not. Existing probe/audit code and
conditional configuration are retained. Fault/reclaim, paging/swap, mapping,
object lifecycle and UMA event delivery still require a matching test kernel.
Marker absence is a review candidate, not evidence that shared tracing is
missing. Review existing shared coverage and disabled/enabled hot-path cost
before proposing additional instrumentation.

Disk reserve monitoring passed. Build timing and resource records are retained
observations, not controlled CPU/memory/disk/cache regression results. Complete
native world/kernel/pkgbase/hardware publication, VM/runtime tests, execution
platform closure and controlled performance qualification remain open. BIP is
excluded. The full-system goal remains active.
