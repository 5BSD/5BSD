# Native kernel installation qualification (2026-11-02)

## Implementation

`//sys/amd64/conf:install_manifest` owns the base kernel installation family.
Its `_metadata` target captures metadata without compiling payloads; its
`_archive` target stages through the existing declared archive backend, source
mtree policies, source account files and SDK tools. No Make invocation or host
installation is part of the native build.

The typed format-5 string setting
`//tools/build/bazel/config:kernel_base_directory` defaults to `/boot/kernel`.
It is separate from standalone modules' existing `kernel_directory` setting
(`/boot/modules`). The existing `kernel_debug_directory` prefix defaults to
`/usr/lib/debug`; an empty prefix places debug files beside the kernel.
Absolute directories are required; traversal and an empty base are rejected.
The existing `kernel_debug` boolean selects the debug file and six unchanged
GDB scripts. Shared directory records are emitted only once when debug files
are colocated. Files use root/wheel/0444; explicit directories use 0755.
The selected Make kernel-install GDB_FILES inventory is declared in source,
not discovered from a build machine's installed files.

## Evidence

Three complete native archives pass `kernel-installation-test.py` against
original Make `kernel-install` invocations in disposable `/usr/obj` stages:

| Profile | Base directory | Debug prefix |
| --- | --- | --- |
| default-r2 | /boot/kernel | /usr/lib/debug |
| alternate | /boot/qa-kernel | /usr/lib/debug |
| colocated | /boot/qa-kernel | empty |

All eight files, script bytes, named/numeric ownership, file/directory modes,
source-policy ancestors and explicit epoch 0 match. Kernel runtime contracts
use the unchanged controlled full-kernel parity test; native and Make separate
debug files independently pass debuglink checks. Whole ELF/debug byte equality
is not claimed. The verifier rejects duplicate/extra/missing archive members,
links/special objects, traversal and unexpected file flags.

A separate debug-disabled metadata build contains only the base directory and
kernel file; this is a metadata check, not a debug-disabled kernel compilation.
Two expected-failure builds verify the precise analysis diagnostics for an
empty base and a traversal-containing base.

Evidence under `/usr/obj/usr/src`:

- `bazel-kernel-installation-{default-r2,alternate,colocated}-20261102`: normal
  build-bsd format-5 builds and immutable artifact captures.
- `bazel-kernel-installation-nodebug-metadata-20261102`: metadata-only capture.
- `bazel-kernel-installation-{empty-base,traversal-base}-20261102`: retained
  expected analysis failures.
- `bazel-kernel-install-make-reference-r1-20261102`: original default Make stage.
- `bazel-kernel-installation-review-r1-20261102`: alternate/co-located original
  Make stages and METALOGs, exact verifier argv, immutable artifact bindings,
  three successful detailed receipts and negative-diagnostic checks.

The original Make stages use the separately compiled controlled Make kernel
from FULL-KERNEL-PARITY-QUALIFICATION.md. Make install dry runs exclude host
bootfile mutation and destructive upgrade branches. All compilation uses the
normal 16-job frontend with disk budget checks; the verifier does no host
installation or tar extraction.

## Integration and limits

Existing build-bsd format-5 targets/build-settings drive the new targets and
setting; no frontend C/schema or backend replacement is needed. The maintained
bsd-build manual documents the setting and scope. The archive epoch is an
explicit macro input; this qualified owner selects 0.

This covers standard amd64 GENERIC kernel filenames/ownership/modes in these
three layouts. Arbitrary KERNEL_KO, owner/mode overrides, modules combined with
the base kernel, native kernel pkgbase creation and package version/flavor
policy remain open. Full world, other architectures/configurations, bootstrap,
hardware/combined publication, VM/runtime and controlled performance gates
remain open. No host installation, upgrade or reboot occurred. Make remains
production/default; BIP remains excluded.
