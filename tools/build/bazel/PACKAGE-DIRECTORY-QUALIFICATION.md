# Package directory ownership qualification (2026-11-02)

## Defect and implementation

The existing package driver compared every layout record against the archive's
non-directory payload inventory. A valid explicit directory therefore failed
before pkg ran. Kernel installation exposed this because it declares its kernel
and GDB directories as first-class installation records.

The driver now compares file/link inventories separately, requires every layout
record to exist in the archive, checks directory type/ownership/mode, and emits
owned directories through pkg's directory plist entries exactly once. Explicit
layout records own their directories directly, including empty directories.
The archive's existing optional directory_packages sidecar supplements mtree
ownership; it need not repeat explicit layout records. Overlapping declarations
must agree, including package tags. Unknown record types and missing payloads
remain errors. No metadata is dropped and no host inventory supplies ownership.

## Checks so far

The maintained pkg-create-directories-test.py uses real pkg and BSD tar:

- Explicit directories with a matching sidecar.
- Existing file-only layout with directory ownership supplied by the sidecar.
- Explicit directories without repeated sidecar records.
- Rejection of conflicting directory package ownership.
- Rejection of a layout directory missing from the archive.
- Rejection of an archive payload missing from the layout.

Successful packages retain payload bytes and persisted directory ownership,
including an empty directory with mode 0750. The old driver fails the valid
explicit-directory case. The fixture names are isolated test inputs.
Host-tool checks pass at /usr/obj/usr/src/bazel-package-directory-driver-review-r3-20261102.
The registered //tools/build/bazel:pkg_create_directories_test passes through
normal format-5 build-bsd bazel-test with the declared SDK Python, pkg, BSD tar,
execution libraries, target SDK ABI ELF and source OS-version header. The test
has no host tool path defaults. Native evidence is retained at
/usr/obj/usr/src/bazel-package-directory-native-r1-20261102, including the original
execution log, frontend receipt, one executed/passing Bazel test report and a
hash-bound detailed receipt with three successful packages and three expected
rejections. The detailed receipt's driver hash equals the current source.
The old-driver preflight failure is retained under
bazel-kernel-installation-review-r1-20261102/package-directory-preflight.

The actual immutable eight-file kernel/GDB installation capture also passes
through this corrected driver and the original UCL generator/templates.
Runtime/debug component package inventories, explicit directories and original
kernels/kernels-dbg set annotations are checked. All eight packaged payloads
also match the immutable archive bytes and tar ownership/modes. Evidence is retained at
/usr/obj/usr/src/bazel-kernel-component-package-driver-review-r3-20261102,
including immutable capture bindings, requests and generated manifests. Earlier
failures remain retained: r1 exposed the optional sidecar semantics; r2 used a
kernel ELF for ABI discovery, which pkg cannot parse. r3 supplies the declared
target SDK userland ELF. The driver does not infer ABI from its host.

This is component driver integration, not a native Bazel kernel package action,
module-complete kernel package, byte-identical Make package archive, repository
publication, host installation or boot qualification. The normal frontend's
format-5 targets/tests mechanism runs this registered test without new C/schema
or manual options. Make remains production/default; BIP remains excluded.
