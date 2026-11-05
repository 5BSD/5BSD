# Shared base data installation (2026-11-05)

## Native implementation

Six original share owners now have native installation artifacts: dict, misc,
skel, mk, keys/pkg/trusted and keys/pkgbase-15/trusted. The keys parent selects
both original leaf archives. Inventories and per-file metadata live directly in
source-owned BUILD.bazel files and use the existing typed installation rules.
There is no Make parsing, hidden file discovery or new Python build driver.

The dictionary retains its relative words -> web2 symlink. Skeleton files retain
0644 modes except dot.mail_aliases (0600). Repository-key payloads retain their
original package ownership and 0644 modes; this copies existing source keys,
not a new repository authorization/signing or key-rotation design. Installed
Make files remain in the bmake package for ports/third-party consumers; helper
shell/Python scripts retain 0555 modes and other files retain 0444. The six test
Make fragments are selected by the native tests setting, matching MK_TESTS.
USB and ee select their actual miscellaneous data; the shared misc directory's
package tag follows the original editor group when ee is enabled.

The first native run built successfully but lacked explicit package-owned
directory records. Those records are now declared. An intermediate exact archive
review also rejected unrelated /etc/pkg directories in a key component. Asking
each leaf for all mtree directories of pkg-bootstrap had expanded its scope.
That request was removed; component archives retain their own declared original
directories and the required ancestors. The comparison was not relaxed to accept
additional package-wide directories.

## Complete selected component comparisons

| Owner | Metadata records | Exact file payloads |
| --- | ---: | ---: |
| dict | 7 | 5 |
| misc (USB and ee enabled) | 20 | 19 |
| skel | 10 | 9 |
| mk (installed tests disabled) | 72 | 71 |
| keys/pkg/trusted | 2 | 1 |
| keys/pkgbase-15/trusted | 3 | 2 |
| Total | 114 | 107 |

All original component records are compared, including six explicit directories
and the dictionary symlink. The audit requires exact inventories, named owners,
groups, numeric modes, package tags, file bytes and link targets. It also checks
tar inventory, types, uid/gid, modes and deterministic epoch zero. Unrelated tar
entries are rejected. Each artifact is resolved through its passed qualification
receipt and immutable manifest/hash binding; original reference source hashes
are rechecked.

The alternate profile disables USB and ee and enables tests for these selected
data components. Original/native misc then has 17 records and 16 files; mk has
78 records and 77 files. Both complete alternate components pass the same checks.
This verifies the actual option branches without enabling an unconverted full
installed-test hierarchy or claiming system test execution.

## Retained evidence under /usr/obj/usr/src

- bazel-share-data-native-r3-20261105: maintained build-bsd, sixteen jobs,
  six installation archives and passing source-settings test. r1/r2 preserve the
  earlier construction states; they are not final component parity evidence.
- bazel-share-{owner}-make-r3-20261105: six independent maintained Make build/
  stage references, with slash-separated owner names hyphenated. These disable
  installed tests and retain the standard object root/profile.
- bazel-share-data-original-review-r2-20261105/review.json: all 114 original
  records and 107 exact file payloads pass; audit source and bindings retained.
- bazel-share-data-options-native-r2-20261105: maintained native alternate
  profile and passing source-settings test.
- bazel-share-{mk,misc}-options-make-r2-20261105 and
  bazel-share-data-options-original-review-r1-20261105/review.json: 95 original
  records and 93 exact file payloads pass for both alternate components.
- bazel-share-data-namespace-r1-20261105/review.json: cross-capture file-claim
  reconciliation with the prior nine-family installation capture: 1120 unique
  archives and 23458 non-directory paths, with zero conflicting file claims. It is not a
  combined full-world build or a directory/package ownership acceptance gate.

## Frontend and remaining work

The existing format-5 frontend carries the component targets and native settings;
the manual describes them. No dispatcher, input-schema, staging/signing or
publication behavior change is needed. No tracked Python implementation changes
are part of this checkpoint. Original program/instrumentation sources are unchanged.

This does not complete share. Remaining content includes docs/examples, firmware,
man pages, the complete source-owned share parent, SNMP, VT, zoneinfo, and selected
locale/encoding integration. Other remaining world roots, installed tests,
Make/pkgbase parity, cross architectures, independent bootstrap, kernel/module
installation, hardware/publication, runtime/VM and controlled CPU/RAM/disk I/O/
footprint/cache/sandbox gates remain open. Make stays production/default. BIP
remains excluded. No host installation, upgrade, publication or reboot occurred.
