# Native CDDL production composition (2026-11-05)

## Source-owned graph

The new //cddl:production_installation_archives composes the six maintained
production subparents: lib, sbin, share, usr.bin, usr.libexec and usr.sbin.
Their labels and configuration selects express original Make ownership; no
Make query, directory scan or Python selection supplies the runtime build graph.
Leaf archive visibility is granted only to its immediate owning parent where
previously private. Existing public producers retain their visibility.

//cddl:production_products also requests libdtotel's regular and PIE archives.
That original INTERNALLIB has no production installation payload; no installed
library is invented and its real build outputs are retained. The complete
installed-test hierarchy and other ABIs are explicitly incompatible at these
production endpoints. This is selected AMD64 production composition.

DTrace selection now includes its original CDDL dependency, including the
experimental section-archive selector. The SPL contribution follows either
DTrace or ZFS selection. ZFS already follows CDDL/OpenSSL/crypt dependencies.

## Dependency corrections exposed by the aggregate

- lockstat relied on private headers formerly inherited from libdtrace. Its
  explicit SPL, Solaris compatibility and system header context now follows
  the maintained Make includes. The original inherited Solaris defines and
  direct elf/dtrace/rt library order are preserved. C sources are unchanged.
- zfs and zpool explicitly declare the Solaris compatibility headers their
  maintained Makefiles select; libintl.h is the original source header. No
  replacement header or undeclared host include is used.
- libumem exposed its private implementation header through public deps. Its
  virtual umem.h overrode OpenZFS's original SPL inline wrappers at zhack.
  The first aggregate failed linking those unintended external calls. An
  attempted extra umem link made construction pass, but strict Make comparison
  caught the extra imports. That link and its Makefile change were removed.
  The actual correction is implementation_deps for the private header and
  explicit header dependencies for libumem's own tests. zhack now retains its
  original unchanged Make library list and matches original ELF interfaces.
- Complete original lockstat/zhack comparisons also exposed absent package-owned
  split-debug directories. utility_debug_directories derives those ancestors
  from package and installation-directory inputs, using the original root/wheel
  0755 metadata and package/dbg tags. Both callers now preserve their original
  records. Other previously unqualified leaves still require full installation
  comparison; this helper does not retroactively establish their parity.

These are native dependency and metadata fixes, not omitted components, host
DSO substitutions, weakened link checks or rewritten program implementations.

## Evidence under /usr/obj/usr/src

- bazel-cddl-parent-native-r1/r2/r3-20261105 retain the actual missing-header
  and unresolved-symbol failures. r4/r5 are intermediate construction successes;
  r5's zhack ELF import comparison failed and is not accepted parity evidence.
- bazel-cddl-parent-native-r6-20261105 passes through normal build-bsd with
  sixteen jobs: 37 installation archives (111 typed archive/request/directory
  outputs) plus both internal libdtotel archives. All fourteen selected test
  targets pass. Three execute in this run: libumem static/shared allocation
  tests and the original ZFS stream queue selftest. Eleven are cached from
  retained passing executions: SPL, AVL, CTF, nvpair, public C++ API, DWatch
  syntax and frontend source-setting tests. These target results are not a
  count of all individual assertions or complete CDDL runtime coverage.
- r6 original-program-review/review.json passes complete original component
  metadata/manual and strict ELF/debug comparisons for lockstat and zhack.
  Exact compressed manual payloads, directories, owner/group/mode/type,
  ordered dependencies, versioned interfaces, hardening and both debug CRCs
  are checked. Native/original binary and debug bytes need not be identical;
  full code/ABI/runtime equivalence is not claimed by these checks.
  Original references: bazel-cddl-lockstat-make-r2-20261105 and
  bazel-cddl-zhack-make-r3-20261105. The latter uses the original Makefile;
  zhack reference r2 includes the rejected extra link and is superseded.
- bazel-cddl-selection-r1-20261105/review.json reconciles all six actual native
  subparent selections against independent Make SUBDIR queries. Immediate
  owner counts are 36 default, 24 without DTrace, 13 without ZFS, zero without
  CDDL, and 13 without OpenSSL. This analysis predates the final experimental
  selector fix; that flag is false throughout these five cases. Source bindings
  retain the exact analyzed revision. This is selection evidence, not compile
  or full installation qualification for all alternative profiles.
- bazel-cddl-disabled-native-r1-20261105 passes after the experimental-selector
  correction, with CDDL disabled and experimental DTrace explicitly requested.
  Both CDDL production endpoints have zero outputs. The actual libutil archive
  contains no DTrace/DOF symbols, and the constructor-registration and frontend
  settings tests pass. disabled-review.json binds the captured archive and
  complete symbol inventory. This does not establish every disabled-world ABI.

- bazel-cddl-tests-enabled-rejection-r1-20261105 explicitly rejects the
  requested production_products target as incompatible when tests=true. The
  dependency chain names the unfinished full installation endpoint; it does
  not silently build a production subset for a full installed-tests request.

## Frontend and remaining work

The maintained build-bsd format-5 interface supports these labels and settings;
no C dispatcher, schema, stage/signing or publication change is needed. The
maintained manual and completion plan describe the composition and limits.

Complete CDDL installed ownership/payload/ancestor-directory and pkgbase parity,
all original test installations, ASAN/TSAN and other feature/architecture
profiles, live DTrace device/probe behavior, ZFS pool operations and service
security remain open. No host pool, module, service or installation is changed
by these checks. Other world roots, complete system/bootstrap/package/hardware/
combined publication, VM and controlled CPU/RAM/disk I/O/footprint/cache/sandbox
acceptance remain required. Make stays production/default; BIP is excluded.
