# Native forty-nine-application rescue construction

## Source-owned system programs (2026-11-05)

The selected AMD64 core adds kldload, kldunload, kldstat, kldconfig, dmesg,
rcorder, mknod, devfs, mount_cd9660, mount_nullfs, mount_unionfs, swapon and
mdconfig. It now links 49 of the default catalog's 103 applications.

Each package owns its rescue sources, local headers and ordered compiler object
selection. Rcorder retains ORDER. Kldload/kldunload retain their module operation
providers; kldstat deliberately excludes its provider under Make's RESCUE policy.
Native geom, bsdxml, kiconv and sbuf archives join the selected original library
order through lazy cc_import dependencies. No SDK library archive substitutes for
these native builds. Bsdxml explicitly grants the rescue package access to its
otherwise private static target. Normal hosted programs remain unchanged.

## Evidence

Evidence is retained under `/usr/obj/usr/src/`.

- `bazel-rescue-49-native-r2-20261105`: normal maintained frontend, sixteen jobs.
  The runtime wrapper passes 68 actual methods, including eleven new argument
  rejection subcases and private rcorder ordering/cycle cases. Source-settings
  passes its separate 28 methods. New host checks reject module/mount/device/swap
  operations before mutation; they do not establish successful privileged behavior.
- Native r1 built and linked but failed two incorrect test expectations. The
  proposed FIFO test misread mknod's one-argument form: maintained source requests
  a character device, and both native and host mknod returned EPERM for this
  unprivileged user. The corrected test passes an invalid device type, requires
  the maintained diagnostic and verifies no path exists; it does not request
  device creation. Rcorder emits "Circular dependency", not "cycle". Its test
  now checks that actual diagnostic and the failing exit status. Failed r1 logs
  remain rejected. Production code and privilege checks were not changed.
- `bazel-rescue-thirteen-more-make-r1-20261105/report.json`: fresh actual original
  generated thirteen `_make` targets, sixteen workers, isolated object roots.
  4532 source/policy/header/tool inputs are bound before/after. Actual nested Make
  recipes produce sixteen C objects and two provider objects, retaining RESCUE,
  normal SSP/debug and no PIE/PIC. Coverage definitions match original conditions.
- `bazel-rescue-49-object-review-r1-20261105/review.json` records all eighteen
  raw compiler/provider comparisons without altering binary data. Twelve C
  contracts match allocated sections, nondebug symbolic relocations and external
  symbols directly. The two traced C objects differ only in DTrace path aliases;
  devfs.c/rule.c retain raw assertion-filename differences. Provider raw DOF/alias
  encoding and complete debug equality remain outside this comparison.
- `bazel-rescue-49-provider-review-r1-20261105/review.json`: both module provider
  pairs pass the maintained ET_REL schema, actual function/relocation/probe-site
  and patched-byte checks. Differing aliases independently match the real object
  path hash. All traced C allocated bytes and nondebug relocation contracts agree.
  Raw DOF-section encoding, registration and live event firing remain unqualified.
- `bazel-rescue-49-filename-controls-r1-20261105/review.json`: isolated original
  devfs compiler recipes with an explicit macro-prefix-map control match native
  allocated/symbolic contracts. Assertions embed the absolute Make source path
  versus Bazel's relative path. Original inputs and objects remain unchanged;
  native flags and bytes are unchanged. This explains the difference without
  claiming raw baseline or DWARF identity.
- `bazel-rescue-49-pipeline-review-r1-20261105/review.json`: fresh original
  crunchgen and generated Make, using identical captured native application,
  archive and startup inputs, match main C and all 100 whole-byte outputs: main
  object, 49 stubs, 49 ld-r/crunchide combined objects and the complete executable.
  AMD64 ET_EXEC, no interpreter/dynamic segment, nonexecutable stack and GNU_RELRO
  checks pass. This proves original pipeline/link behavior on identical inputs;
  it is not independent reconstruction of every library or world.

## Integration and remaining gates

The existing maintained format-5 targets/settings and SDK support these native
contributions. The frontend manual, completion plan and observability ledger are
updated. No C dispatcher/schema, signing, installation or publication helper change
is needed. Make stays production/default; BIP remains excluded. No host
installation, upgrade or reboot occurred.

Complete the remaining 54 default applications, actual rescue library variants,
configuration/architecture selection and complete installation/debug/metadata/
pkgbase behavior. Positive module load/unload, mount/unmount, device creation,
GEOM attachment and swap operations need dedicated disposable VM qualification;
host argument rejection does not substitute for it. Full rescue/helper-path,
world/kernel/modules, bootstrap, hardware/combined publication, runtime and
CPU/memory/disk/cache/sandbox gates remain open.
