# Complete stat/readlink/mountpoint parent installation

## Change and result (2026-11-06)

The stat installation parent now conditionally includes all three original shell
ATF programs and the complete Kyuafile. The tests feature selects their manifest,
original tests-package directory policy and source bodies. No case list is used
to select installed bodies; the complete scripts are retained. The existing
stat/readlink/mountpoint hardlinks, manual aliases, program, DTrace definitions
and production debug policy remain source-owned and unchanged.

Independent original Make parent controls pass with tests enabled and disabled.
Normal build-bsd format-5 native requests pass in both modes. Complete comparisons
match 11/7 file/link paths and 3/2 explicit directory claims, including named
owners, modes, package tags, exact non-ELF data and actual hardlink inode identity.
The tests-disabled native tar is byte-identical to the before-change capture.
The three installed ELF names pass original Make metadata/ordered-dependency
comparison. Native and original stat split-debug separation/name/CRC checks pass.
Full ELF bytes and DWARF/debugger equivalence remain outside these checks.

All 26 original cases are discovered from the installed complete scripts:
mountpoint_test (13), readlink_test (3), stat_test (10). Native/Make discovery output
matches exactly under the same explicitly hash-recorded host /usr/libexec/atf-sh.
This is host-interpreter metadata discovery, not native ATF runtime qualification.
No original body executes here. Mount/jail/chroot cases remain for a qualified VM;
ordinary cases also need actual native runtime execution before acceptance.

## Evidence

All directories are under /usr/obj/usr/src:

- bazel-stat-parent-make-r1-20261106 and
  bazel-stat-parent-no-tests-make-r1-20261106: independent original controls.
- bazel-stat-before-no-tests-native-r1-20261106: unmodified production baseline.
- bazel-stat-parent-native-r1-20261106 and
  bazel-stat-parent-no-tests-native-r1-20261106: maintained frontend captures.
- bazel-stat-parent-review-r1-20261106 and
  bazel-stat-parent-no-tests-review-r1-20261106: complete installation comparisons.
- bazel-stat-parent-binary-review-r1-20261106: all three ELF metadata reports.
- bazel-stat-parent-final-review-r1-20261106: immutable bindings, debug checks,
  exact negative archive comparison and all 26 original metadata identities.

Existing format-5 tests inputs and maintained backend/capture APIs suffice; no
C/frontend/signing option changes are needed. The frontend manual documents the
conditional parent. The whole usr.bin tests-enabled aggregate remains guarded;
this one completed installation parent does not close that root, body/VM,
world/kernel/module/package/cross-platform/performance/bootstrap/publication
qualification. Make remains default; BIP is excluded.
