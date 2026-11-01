# Ordered dynamic dependency qualification — 2026-11-01

## Default gate

`elf-artifact-check.py` now rejects a different ordered `DT_NEEDED` vector for
both programs and shared libraries. Equal dependency sets are insufficient:
lookup order can change symbol resolution. There is no order-ignore switch.
The existing identity, hardening, import/export/version and archive gates remain.
Section hashes still report differences; this helper does not establish runtime
behavior or full ABI/byte parity.

`elf-needed-order-test.py` takes explicit `--program`, `--shared`, `--soname`,
`--readelf`, `--objcopy`, and a fresh `--work` directory. It checks identical real
ELFs, then swaps two dynamic entries in private negative copies. Parsed metadata
other than order must remain equal, the checker must reject the changed order,
and original input hashes must remain unchanged. The copies are test mutations,
never build candidates or rewritten parity outputs. The final report binds the
checker, test, inspector and original input hashes. This standalone oracle test
uses explicit inspection tools; it is not represented as a native Bazel test.

Evidence under `/usr/obj/usr/src/`:

- `bazel-elf-needed-order-before-20261101.log` retains the original checker
  incorrectly accepting the program negative (the regression fails as intended).
- `bazel-elf-needed-order-final-20261101/` records both identical positives and
  both reordered negatives passing with the strict gate. Inputs are the real
  Make bhyve executable and staged `libradius.so.4` (crypto then libc).
- `bazel-elf-artifact-regression-20261101.log` records all six existing program /
  archive positive and mutation-rejection checks passing.

## bhyve native link correction

Make's maintained HyperTrace LDFLAGS prefix precedes its LIBADD. Native bhyve now
expresses that complete prefix as ordinary final `cc_binary` dependencies and
`dynamic_deps`: proc, ctf, elf, z, rtld_db, thr, util. The source groups consume
header-only zlib/libutil dependencies; repeated link edges in those groups had
caused rules_cc's link-order deduplication to retain the old suffix positions.
Public pthread headers remain declared SDK inputs. No raw link command,
handwritten ELF adjustment, source-path constant or toolchain policy change was
introduced. DTrace source/provider object grouping remains unchanged.

The first prefix-only attempt built successfully but the strict comparison
rejected its unchanged order. Its receipt and actual link parameters are retained
as `bazel-bhyve-link-order-qualification-r1-20261101` and
`bazel-bhyve-link-order-capture-20261101.*`. The corrected normal frontend build
is `bazel-bhyve-link-order-qualification-r2-20261101`, two targets with no runtime
tests requested. Its actual CppLink, parameter-file digests and immutable output
binding are in `bazel-bhyve-link-order-capture-r2-20261101.*`.

The pre-merge Make reference was rejected by input-hash validation: HyperTrace
merge `9a4d5d98d64` changed six C/header inputs. Its comparison cannot qualify
current sources. `bazel-bhyve-link-order-make-r2-20261101` is a fresh independent
-j16 Make build/install reference with final input checks. The r3 ELF audit uses
this current reference and the immutable r2 native capture. Its complete ordered
vector is equal:

```
libproc.so.5 libctf.so.2 libelf.so.2 libz.so.6 librtld_db.so.2
libthr.so.3 libutil.so.10 libvmmapi.so.7 libmd.so.7 libnv.so.1
libuvmem.so.1 librt.so.1 libsbuf.so.6 libcam.so.7 libprivate9p.so.1
libprivateucl.so.1 libxo.so.0 libnetgraph.so.4 libcrypto.so.35
libssl.so.35 libc.so.7
```

`bazel-bhyve-link-order-install-audit-r3-20261101/report.json` passes all 86
installed paths, literal payloads and metadata plus four debug-link CRCs. The
repeated `/usr/lib/debug/usr` directory retains its two genuine Make package
contexts; this compares final per-path metadata, not complete split-package
ownership. The 18 GiB start / 16 GiB reserve disk guard did not interrupt either
native run. No host install, VM, guest execution or hardware activation occurred.

## Residual gates

- The current-source r3 ELF audit still reports `.SUNW_dof`, `.text`, `.rodata`,
  relocation/dynamic/symbol sections and DWARF differences. Printable `.rodata`
  inspection concretely finds relative native versus absolute Make diagnostic
  filenames, plus one native virtual-include spelling for `pci_emul.h`.
  `bazel-bhyve-link-order-rodata-review-20261101` retains original section bytes,
  input hashes and string-set differences. This explains observed strings, not
  every byte/code/DOF difference; full object, instruction and probe parity
  remains open. No blanket path explanation or runtime/performance claim.
- Only the maintained default amd64 profile was qualified here; DTrace-disabled
  and other option combinations, full bhyve tests and guest lifecycle remain open.
- `otel-probe.py`, `protobuf-probe.py`, and `dtrace-probe.py` call this shared
  checker and therefore inherit the strict gate. Their historical report-only
  order differences are not order qualification. In particular the documented
  hwstat/bsdinstruments/dtrace executable order differences require native graph
  fixes and new immutable comparison evidence before those probes can pass.
  otel's diagnostic Make-order relink occurs after the comparison and cannot
  bypass this failure. No caller was given an escape or diagnostic substitute.

The existing format-5 `build-bsd bazel-test` path builds and captures the changed
native targets. No new frontend input or C dispatch/backend target is needed.
The maintained manual and completion plan record this stricter verification gate.
