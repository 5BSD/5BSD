# Native manual database construction

## Typed inputs and native execution (2026-11-05)

The new `bsd_man_database` rule consumes declared installed records and file
artifacts from installation archives/sets. It selects a canonical manual root,
rejects duplicate destinations and self-indexing, resolves hardlink chains with
the existing linear resolver, and declares only selected regular manual payloads
as action inputs. It does not parse Make metadata or installation tar files to
discover its native graph. Installation records and source artifacts now travel
through the archive providers without changing existing serialized outputs.

Execution-expanded trees retain explicit bounded prefixes, tree artifacts and
metadata artifacts in those providers. An unrelated tree is excluded; a tree
intersecting the requested manual root is rejected instead of silently omitted.
Such a corpus needs an explicit supported inventory before indexing. Current
execution-expanded timezone production archives exercise provider compatibility.

A bounded Python driver materializes the selected corpus on disk in temporary
storage under the output directory. It preserves real hardlink inode identity,
validates/rebases symlinks inside that corpus, invokes the declared generator,
copies the database output and removes temporary files. Starlark owns selection,
input dependencies and generation actions; Python performs physical staging.
No Make invocation or source-tree walk runs inside native generation.

The execution tool builds from the maintained mandoc sources with Bazel's fully
static link feature and an explicit makewhatis invocation alias. The original
installed mandoc target retains its existing sources and linking policy. A
retained hash-bound observed execution ELF has neither an interpreter nor shared
library dependencies. This does not establish a complete source bootstrap.

`//share/man:selected_database` is explicitly the configured shared-manual corpus.
It is not the installed-world database: program/library/OpenSSL manuals must join
world finalization before the complete etc afterinstall phase can be qualified.
The rule emits a normal typed installation manifest for a 0644 root/wheel database
without invented package tags, matching the original makedb metadata policy.

## Accepted evidence

All evidence is below `/usr/obj/usr/src/`.

- `bazel-man-database-native-r4-20261105`: maintained build-bsd bazel-test using
  sixteen jobs. Source-settings and the new three-method database suite pass.
  Tests index and query compressed manuals through direct, chained hardlink and
  chained symlink names; reject escaping/dangling/cyclic aliases and invalid
  destinations/hardlink roots; and verify temporary-stage cleanup.
- `bazel-man-database-tool-make-r1-20261105`: independent original Make mandoc
  build/install reference with sixteen jobs and current source bindings.
- `bazel-man-database-corpus-make-r1-20261105`: fresh independent full share/man
  build/stage with the selected profile and sixteen jobs.
- `bazel-man-database-review-r1-20261105/review.json`: all 4248 manual paths,
  exact source payloads and metadata, and 1426 physical inode groups reconcile
  against the original corpus. The comparison copies that independent corpus
  while retaining inode equivalence, then runs the maintained Make makedb target
  with the independently Make-built mandoc tool. Database bytes match exactly:
  SHA-256 `a7ec9742a399a96dbe0c53487e1f1173aa3f1e4ab1ab17cccf29df2748a080fc`.
  The bounded original control explicitly disables the separate OpenSSL root;
  it does not substitute an empty OpenSSL corpus for full-world qualification.
- `bazel-man-database-final-review-r1-20261105/review.json`: final database and
  variant with unrelated timezone archives both match that independent result.
  An actual uncached variant action declares 1426 selected regular manual inputs
  and no timezone payloads or installation tar artifacts. The execution tool is
  copied only after matching its observed action input digest, then its ELF is
  inspected and retained. All 33 existing manual archive/metadata/directory
  outputs remain unchanged. Decoder, action log, artifacts, audits and tool/control
  receipts are hash-bound. This is bounded dependency/stability evidence, not
  general incremental/cache/sandbox or performance acceptance.

## Rejected attempt and remaining gates

Native r2 completed database generation but failed a query test. The test had
removed the installed files that apropos validates against its database. The test
now supplies those paths and exercises every alias name; r3 and final r4 pass.
The failed capture remains rejected. Native r1 was an earlier successful generator
checkpoint before the hardened chain handling and complete test suite.

The normal format-5 target/output interface supports these database artifacts;
the frontend manual and completion plan are updated. No C dispatcher/schema,
signing or publication helper change is needed. No full-world namespace count is
advanced by the selected database fixture. Empty-corpus installation/query behavior,
OpenSSL and complete installed-world composition, additional layouts/ABIs and
execution-expanded manual inventories remain unqualified.

Next wire the complete world corpus into finalization, complete etc installation
and afterinstall, and finish rescue/sys/stand/world and installed tests. Full
installation/debug/pkgbase, reproducible bootstrap, cross/runtime/VM and CPU,
memory/disk/cache/sandbox gates remain open. Make remains production/default;
BIP remains excluded. No host installation, publication, upgrade or reboot occurred.
