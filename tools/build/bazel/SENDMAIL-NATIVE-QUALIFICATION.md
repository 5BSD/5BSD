# Native sendmail administration checkpoint (2026-11-05)

## Native implementation

All five original usr.sbin SENDMAIL owners now have source-owned native targets:
editmap, mailstats, makemap, praliases and sendmail. They use the existing native
libsm, libsmdb and libsmutil PIE producers and explicit shared dependencies.
Main-program feature selects preserve NIS, IPv6 support, OpenSSL STARTTLS/TLS_EC
and TCP wrappers. The OS header comes from the source-owned libsm header
provider. No Make query, source-list discovery or Python compilation pipeline
feeds these native targets.

The main daemon installs under /usr/libexec/sendmail, group smmsp, mode 2555.
The explicit sendmail_set_user_id setting selects Make's opt-in 4555 mode. This
changes installation metadata only and does not execute setuid software.
Original mailq/newaliases/aliases manuals and hoststat/purgestat manual hardlinks
are retained. The four companion tools and their manuals belong to utilities,
as actual Make metadata establishes; only the main daemon belongs to sendmail.
An initial candidate assigned all five to sendmail and was corrected before
accepting the final original-component comparisons.

## Retained evidence under /usr/obj/usr/src

- bazel-sendmail-native-r1-20261105 passes initial five-program construction,
  all three PIE archives and the existing libsm tests. Its initial companion
  package ownership is superseded by r2.
- bazel-sendmail-native-r2-20261105 passes through normal build-bsd with
  sixteen jobs. The parent contributes 358 installation archives in this
  SENDMAIL-enabled/NIS-disabled profile. All six requested test targets pass:
  source settings plus libsm match/string/strio/scanf/strl. Cached test outcomes
  remain identified in the native receipt; no SMTP test is implied.
- Its original-review/review.json independently compares all five complete
  original component metadata sets, archive owner/group/mode/type/epoch,
  exact compressed manual payloads and manual hardlink relationships. Strict
  ELF ordered dependencies, versioned imports/exports and hardening match.
  Native and original debug CRCs pass. Full executable/debug byte identity
  and complete ABI/runtime parity are not claimed by these checks.
- Original references are bazel-sendmail-program-make-r2-20261105 and
  bazel-sendmail-{editmap,mailstats,makemap,praliases}-make-r1-20261105.
  Each is independently built and staged using maintained install-reference.py
  with complete original installconfig recursion and recipe metadata.
- bazel-sendmail-standard-libraries-make-r2-20261105 rebuilds original libsm,
  libsmdb and libsmutil at standard object locations, ordering clean before
  parallel all. Source, command and archive hashes are retained. Original
  program link metadata proves use of those exact PIE archives, and hashes
  are rechecked after comparison. No source-layout guard is weakened.
  r1 is superseded because it requested clean and all together.
- r2 original-review/archives.json establishes member order and symbols for
  all three native PIE archives against those fresh original archives. This
  is not archive byte identity or full object-code equivalence.
- bazel-sendmail-native-r3-20261105 passes combined NIS/SENDMAIL construction
  with 368 administration installation archives and all ten selected test
  targets. Its setuid-selection-review.json verifies the captured 4555 smmsp
  installation request; no privileged execution occurs. This combined profile
  does not inherit the NIS-disabled program's original linked-parity claim.
- bazel-sendmail-selection-r1-20261105/review.json reconciles the actual
  configured native parent against all 261 original immediate Make owners in
  the combined expanded profile, without missing or extra owners. This is
  selected construction coverage, not complete world/installation coverage.
- bazel-sendmail-native-r4-20261105 passes all five programs and six selected
  test targets with OpenSSL, TCP wrappers and IPv6 support disabled. Original
  linked comparison for this alternative profile remains open.

## Frontend and remaining acceptance

Existing build-bsd format-5 labels/settings support the targets and new metadata
selector. The maintained manual is updated and captured in the qualified parent;
no C dispatcher, schema, signing or publication change is required.

Custom SENDMAIL_CFLAGS/DPADD/LDADD/LDFLAGS configuration still needs explicit
native inputs and dependency semantics. No ambient Make environment is silently
imported. Service configuration generation and the complete mail system outside
these five owners still need whole-world ownership/install review.

Mail delivery, SMTP/TLS, relay authorization, queue operations, map updates,
privilege dropping, logging/audit/probe delivery, boot/runtime and performance
are unqualified here. Installed tests and other ABIs remain gated at this parent.
Other world-family closure, cross-architecture/configuration coverage, legacy
libc ABI migration, the outstanding NIS original linked references, complete
world/kernel/module installation/pkgbase, reproducible bootstrap, separate
hardware and verified combined publication, VM and CPU/RAM/disk I/O/footprint/
cache/sandbox acceptance remain open. Make stays production/default and BIP is
excluded. No host installation, upgrade, publication or reboot is performed.
