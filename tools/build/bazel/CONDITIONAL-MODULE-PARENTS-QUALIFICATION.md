# AMD64 architecture and source-option module parents (2026-11-06)

## Source-owned declarations

Nineteen additional source parents now declare typed module sets and base
installation targets. They preserve parent-owned KMOD products alongside their
children (AAC/AACRAID, IPMI, MFI/MRSAS and BHND), AMD64 architecture branches,
nested sound/libalias families, ACPI, SPI, PWM, I2C controllers, VMware, AXGBE,
DTrace and Chelsio/VirtIO traversal. Source membership stays in checked-in BUILD
files; leaf producers retain compilation, package and installation policy.

VirtIO's DTrace frontend is selected by the existing dtrace setting. Chelsio's
OFED integration is selected by the existing ofed setting. These controls match
original Make's MK_DTRACE/MK_OFED branches. Other architecture-specific declarations
remain explicitly AMD64: they do not claim ARM64/RISC-V coverage or substitute
host architecture. Root and kernel-option-dependent traversal remain future work.

A one-time reviewed policy/migration writes source declarations and retains before/
after hashes and prior BUILD files. Production actions do not parse Make, call Make,
read an installed tree or consume a frozen selected-module list. The independent
review runs original Make only as a reference and checks its actual SUBDIR and
KMOD values against the typed native outputs.

## Results and retained evidence

Paths below are relative to /usr/obj/usr/src:

- bazel-conditional-module-parent-migration-r1-20261106 retains the policy, migration,
  original existing source declarations and exact Make/include/BUILD hashes.
- bazel-conditional-module-parents-native-r1-20261106 passes all thirteen test targets
  and builds/captures all requested sets and installation manifests through the
  maintained format-5 frontend with sixteen jobs. Test executions may reuse valid
  cached results; all producers are not described as freshly recompiled.
  Receipt SHA256 50337d4ef3a6b721e05ee10955ce1294828ca4858c1b5d77e21d527ccbbe9c1b
- bazel-conditional-module-parents-review-r2-20261106/review.json verifies every
  parent SUBDIR and parent-owned KMOD against original Make, complete nested member
  coverage, all runtime/debug/alias installation records and actual product bindings.
  Every producer's owner/group, numeric mode, package/debug tags and link policy
  match Make. All 127 real module ELF/debug-link/CRC pairs pass. Three BHND core
  members overlap the preceding static cohort, giving 258 unique modules across
  43 source parents in the combined hierarchy.
  Review SHA256 38b44ce7ae7615de20eb49ccd8915479eeb3368b55792b1e9939679a48662442
- bazel-conditional-module-parents-off-native-r1-20261106 builds real VirtIO/Chelsio
  sets with dtrace=false and ofed=false. It has tests=[]; it is artifact/selector
  qualification, not executed runtime cases.
  Receipt SHA256 10ffbca706d71fc6a197d1771213ee7287ec7a6c0da25a450ba6d93390839b33
- bazel-module-parent-selectors-review-r2-20261106/review.json checks the disabled
  source flags against actual Make. VirtIO selects 19 rather than 20 modules;
  Chelsio selects 14 rather than 15. Exactly virtio_dtrace and iw_cxgbe are removed.
  All 33 remaining products retain identical configured runtime/debug output names,
  bytes and metadata. No unselected module appears in the installation records.
  This is payload/selection consistency, not a controlled cache-performance result.
  Review SHA256 e5b02900e76a604003a8e534833f1557640f66610b3f0237690590494b99391f

The initial parent review incorrectly required every producer to have empty SUBDIR,
which rejected explicitly modeled parent-owned modules. The corrected reviewer
requires their declared children to match Make and still rejects unmodeled child
traversal. The initial selector reviewer compared canonical @@// labels with //
display spelling; it failed before Make comparison. Canonical label handling fixes
that observer without changing native selection or acceptance expectations. Both
failed reviews and their explanations are retained separately.

## Coverage limits and frontend review

This does not establish a complete installed kernel, linker.hints, actual kernel/
world package construction, new independent Make machine-code compilation,
module loading, hardware or service runtime, a normal boot, upgrades or other
architectures. Kernel-option-controlled parents still need shared explicit option
authority before root traversal is complete. Legacy AIC7xxx children lack native
producer declarations and are not silently represented by an incomplete parent.
They remain a recorded optional-module gap rather than a converted group.

Existing format-5 targets and source settings express all inputs, including both
selector alternatives. Source parents, tests/evidence and maintained manual are
updated together. No new build-bsd C option, staging/signing/verification/publication
contract or default backend change is needed. No host kernel/module installation,
module loading, upgrade or reboot occurred. Standard /usr/obj and separate hardware/
combined publication requirements remain unchanged. Make stays production/default;
BIP remains excluded. Continue root/conditional/kernel-option traversal, full
kernel/pkgbase, normal startup/services, real upgrades, architecture, bootstrap,
cache/sandbox/reproducibility/debug/resource and combined-publication gates.
