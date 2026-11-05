# Complete native libc string-test construction (2026-11-05)

## Implementation

All 42 original programs (28 local and fourteen imported NetBSD) now compile and
install through source-owned native rules. Explicit source aliases preserve the
local memset2/strcmp2/strerror2/strrchr2 roles alongside similarly named imported
programs. There is no source discovery or Make invocation during native builds.
All programs retain original -fno-builtin, warning, PIC/PIE and package/debug
policy. Only imported programs receive NetBSD compatibility inputs; only memchr
and memcpy receive libmd. Native public libc/ATF interfaces and selected native
libmd runtime are declared.

Eight wrapper translation units retain their original shared C body inclusion.
Each consumer depends only on its actual body, declared through a dedicated
cc_library textual_hdrs entry. The bodies are not independent translation units
or ordinary module headers, and unrelated test targets do not inherit them.
Per-program source/textual/case/library inventories are validated against actual
program names. The same libmd selection drives link and runtime dependencies.

A single program inventory drives complete installation and the sorted original
Kyuafile: 42 executables, 42 split-debug files and one Kyuafile. Typed archive,
metadata and directory-policy providers remain available for parent composition.
No original C source or test algorithm is rewritten to accommodate Bazel.
The current source-owned runtime subset contains 31 original cases; it is not
substituted for the complete installed ATF program inventory.

## Evidence

All directories below are under /usr/obj/usr/src.

- bazel-libc-string-native-r1-20261105: maintained build-bsd bazel-test, AMD64,
  sixteen jobs. Complete installation builds and 25 local bit-search, version
  comparison and bounded-length cases execute freshly and pass. Source-settings
  is cached. Inputs are bazel-libc-string-request-r1-20261105/inputs.json.
- bazel-libc-string-native-r2-20261105: six original memchr/memcpy/memccpy cases
  execute freshly with declared native libmd as well as libc/libsys/ATF. All 32
  targets pass (six fresh, 26 cached). Thus all 31 selected runtime cases pass.
- bazel-libc-string-review-r1-20261105/review.json: complete independent comparison
  against the fresh original libc parent at
  bazel-libc-installation-make-r1-20261105. All 85 installed file inventories,
  owner/group/mode/tags/flags and exact Kyuafile bytes agree. All 42 program ELF
  identity, PIE/interpreter, ordered dependencies, dynamic symbols/versions and
  hardening contracts match. Both original and native debug filenames and CRCs
  are checked. Original program/debug payloads match their Make METALOG hashes.
  Original source inputs remain checked separately from native declarations.
- bazel-libc-string-native-r3-20261105: final explicit textual_hdrs graph passes
  all 32 targets from cache. The final-bindings-r1 review verifies all three
  archive/metadata/directory outputs identical to the independently reviewed r2
  capture. Changing the header classification does not alter installed bytes.

These results establish construction, complete selected installation metadata,
bounded ELF interfaces/debug coherence and selected arithmetic/memory/string
runtime cases. Raw program/debug byte equality, complete ABI/semantic parity and
a fully hermetic dependency closure are not claimed. DOF initialization is
explicitly disabled; runtime probe firing and audit delivery are not qualified.

## Remaining work and frontend

Other string cases, locale/data-sensitive execution, the complete installed test
hierarchy and parent Kyua/helper/data traversal remain open. Test-enabled parent
guards remain active. Other ABIs/options, source-owned archive ordering,
independent whole-world/debug/pkgbase parity, bootstrap, VM/service/runtime,
hardware/publication and CPU/memory/disk/cache/sandbox gates remain required.

Existing format-5 targets/tests and the maintained backend express the new
contribution. No C frontend, staging/signing/publication or security-policy change
is needed. The manual and completion plan document its scope. Make stays
production/default; BIP is excluded. No host installation, upgrade, reboot or
service reconfiguration occurred.
