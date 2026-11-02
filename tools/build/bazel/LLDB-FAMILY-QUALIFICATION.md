# Selected LLDB family composition (2026-11-02)

## Native products and installation contexts

`//lib/clang:debugger_products` selects the qualified private LLDB DSO and the
original driver/server programs with the existing typed `lldb` setting.
`debugger_installation_archives` collects their three separate archives through
the existing `bsd_install_archive_set`; it preserves each component manifest
and directory/package context. Private Clang/LLVM and system runtime packages
remain separate dependencies, as in the existing compiler installation graph.
This debugger subset does not claim the entire `lib/clang` or world parent.

`debugger_safe_tests` has fixed explicit membership: the private library API
wrapper and the two CLI wrappers. The actual tests use compatibility based on
the existing `tests` and `lldb` settings. A nonconfigurable Bazel suite does not
hide a disabled feature behind a successful empty run. Only narrow family-owner
visibility was added to the CLI tests and archives.

All evidence below is under `/usr/obj/usr/src`:

- `bazel-lldb-family-default-native-r3-20261102`: ordinary maintained frontend,
  current `bazel-posttar-sdk-20261102`, jobs16 and the established 18 GiB start /
  16 GiB reserve guard; three actual native safe wrappers pass. This includes
  the library version/error/string/JSON checks and six source-reviewed CLI
  paths before debugger initialization. Native private DSO loader checks pass;
  DOF is disabled before startup. These are three XML wrapper cases, not the
  upstream suite, debugger attach/launch/listen or a hermetic loader claim.
- `bazel-lldb-family-composition-review-r1-20261102`: all three runtime product
  payload hashes and all nine archive/manifest/directory-context hashes match
  the prior immutable, independently qualified component captures. All fifteen
  original Make installation records are retained in their component contexts.
  Repeated directory entries are not silently flattened or retagged. See
  LLDB-LIBRARY-QUALIFICATION.md and LLDB-CLI-QUALIFICATION.md for actual compiler,
  independent Make, original/control filename policies and payload proof.
- `bazel-lldb-family-disabled-native-r1-20261102`: `lldb=false` builds the two
  family collection targets with zero selected files and zero payload bytes.
- `bazel-lldb-family-disabled-tests-native-r1-20261102`: explicitly requesting
  the disabled suite yields three incompatible configured tests and is rejected
  before execution with `requested tests expand to no compatible configured tests`.
  The expected nonzero result is retained; it is not reported as a test pass.

Initial default r1/r2 attempts rejected missing family visibility to the two
CLI tests and then the two CLI archives. Both are preserved. The corrections
expose only the legitimate `//lib/clang` owner and do not change program objects,
link flags, installed payloads or test bodies. Existing format-5 targets,
settings, test inventory and archive-set support suffice; no new frontend C,
backend, signing, staging or manual interface is introduced.

## Original parent selection and current world inventory

`bazel-lldb-family-parent-reference-r1-20261102` queries original Make in the
bound selected-world environment for four cases across `lib`, `usr.bin`,
`lib/clang` and `usr.bin/clang`: default, LLDB disabled, only LLDB enabled among
Clang/LLD/LLVM-binutils/LLDB, and all four disabled. It binds actual Make include
files, export names and explicit option arguments. With LLDB disabled, only
liblldb and the two CLI entries disappear from their corresponding default
child lists. With only LLDB enabled, both top-level clang parents are selected;
its library parent orders libllvm/libclang/headers/liblldb and its program
parent orders lldb/lldb-server. With all four disabled, both top-level parents
omit clang. The native debugger subset follows its three selected components
in that original order; dependency package installation remains separate.

`bazel-world-inventory-lldb-family-20261102` is a fresh successful invocation of
the maintained recursive Make `print-dir` inventory, using the original bound
public trust anchor. It observes 2,128 configured directories and includes all
three LLDB components through the actual recursive parent traversal. Relative
to the retained 2,127-directory postmerge inventory, the sole added selected
directory is `sbin/mount_virtiofs`; no directory was removed. These are recursion
observations, not native compilation or complete package coverage counts.

The full world aggregate, all bootstrap phases and parent export/override
coverage remain separate completion gates. Next userland work is reconciling selected products, actual native actions and
aggregate ownership. mount_virtiofs already has a tracked native graph and
October 26 component qualification, despite its later addition to recursive
Make selection; it is not a newly identified missing conversion. Its post-merge
revalidation obligations remain separate. Other architectures, static LLVM linking,
full upstream debugger execution, final package creation and whole-system
runtime qualification remain open. No host installation or reboot occurred.
