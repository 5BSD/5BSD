# Configured userland coverage review queue

2026-11-01. This is the refreshed inspection queue for the full native Bazel
completion plan. It does not establish native world, package or runtime
completion. Make remains the production/default backend. BIP is out of scope.

## Fresh configured inventory

The maintained inventory pipeline completed against /usr/src and the explicit
/usr/obj/usr/src/amd64.amd64 world profile, using sixteen query workers and the
existing public loader trust anchor. It did not install or sign anything.
All evidence paths below are under /usr/obj/usr/src:

- bazel-world-inventory-refresh-20261101/inventory.json: successful maintained
  Make print-dir recursion, 2,127 unique selected directories, no diagnostics;
- bazel-world-components-refresh-20261101/summary.json and components.jsonl:
  all 2,127 directories queried successfully, zero failed components, with
  actual target/profile/Make include closure and source input bindings;
- bazel-world-native-survey-refresh-20261101.json: metadata versus local or
  ancestor BUILD-file presence, including all supplied input hashes;
- bazel-world-source-owner-review-20261101.json: a narrower inspection list of
  explicit PROG/PROG_CXX plus SRCS components without a local BUILD file.

The source-owned tools are world-inventory.py, world-components.py and
world-native-survey.py in this directory. Re-run them with fresh /usr/obj output
paths whenever configuration or source selection changes. The inventory call
uses --src /usr/src, --objtop /usr/obj/usr/src/amd64.amd64,
--profile /usr/obj/usr/src/amd64.amd64/.src_opts, --jobs 16 and explicit
--trust-anchor /usr/obj/usr/src/loaders/production-loader-20261024/anchors.pem.
The component query consumes its inventory.json; the native survey consumes
its component-query directory. Their captured records are the detailed source
of the queue; this prose is not the build graph or a file-protection policy.

The refreshed selection has 24 additional directories compared with the
2026-10-30 inventory: DTotel/OTel components, protobuf/Abseil dependencies and
tools, and base-accounts. None of the older selected directories disappeared.
This inventory is the configured native amd64 world. It is not an ARM64 or
RISC-V64 world inventory or a bootstrap phase inventory.

## Presence observations, with strict limits

| Directory category | Local BUILD file | Ancestor BUILD file only |
| --- | ---: | ---: |
| All selected directories | 1,418 | 709 |
| Declares program metadata | 843 | 153 |
| Declares library metadata | 346 | 76 |
| Declares script metadata | 191 | 291 |
| Declares test metadata | 207 | 162 |

Categories overlap; rows do not add to a total number of products. Directories
can define multiple programs, libraries, scripts or suites. A BUILD file may
contain only exports or imported upstream metadata; an ancestor may already own
actual child targets. The working tree included the pending base-accounts
candidate during this survey. Its package-file presence is not qualification.
No row is an action, installed-file, test-case or completion percentage.

## Concrete next source-owner review

The narrower PROG/PROG_CXX plus nonempty SRCS inspection yields 39 directories
without local BUILD files. This predicate is not a complete missing-product
inventory: it excludes multi-program and generated/data-only forms, and still
requires checking ancestor ownership before adding a new package.

- Twenty are boot/loader helpers under stand/, including EFI loader variants,
  BIOS/BTX paths, kboot and the userboot test. Preserve real target toolchains,
  assembly, generated/linker inputs and installation, rather than wrapping Make.
- Four are filesystem test helpers under tests/sys/cddl/zfs and pjdfstest.
- Fifteen ordinary program candidates are lldb, lldb-server, apm, cxgbetool,
  dtracedctl, mailwrapper, mlx5tool, ppp, pppctl, switchboard-nss and the five
  selected WPA programs (hostapd, hostapd_cli, wpa_cli, wpa_passphrase and
  wpa_supplicant). Inspect actual expanded sources/private libraries/options
  before declaring target ownership; the source count in Make metadata alone
  is not a complete generated/dependency closure.

Review the 291 script-category and 162 test-category directories with only
ancestor packages as well. Many are recursion/group directories or children
already owned elsewhere; do not turn these counts into invented missing
programs or generate production BUILD files from the survey. Existing local
native declarations also need actual configuration, source/action, debug/probe,
installation, package and test evidence, not just a source-file count.

## Current coherent userland work

The bsdtrace component was committed as 7765d7618af with fourteen actual GNU C17
compile actions, 763 Make source/header checks, all nine installation records,
ELF/dependency order and debug CRC checks, and eleven original safe ATF passes.
Its two installed-path cases, live hardware, cross-userland and wider package/
performance gates remain open; see BSDTRACE-QUALIFICATION.md.

The base-accounts default component now passes native build/install and all
eleven original ATF cases at their normal installed paths in a disposable
guest. Its nine component installation records and all six literal payloads
match independent Make output. UID/GID/group checks, private test-root removal,
fixture input integrity and wrapper mount cleanup pass; no source cases were
dropped or rewritten. The actual native pw/pwd_mkdb absolute-helper chain is
exercised. See BASE-ACCOUNTS-QUALIFICATION.md for the bootstrap boundary,
resource evidence and preserved failed host attempts. The unused generic ATF
environment/text-helper experiment was removed from active source.

The separate test-disabled/manpage-split selector also passes: six component
records and four literal payloads equal independent Make output, component
tests are absent and the manual belongs to runtime-man. Mailwrapper now also passes ten configuration comparisons and 84 unique
installation records, including actual conditional MTA configuration/aliases,
four program ELF contracts, eight debug CRC checks and four unprivileged
dispatch/error cases. The corrected compiler action matches Make warnings,
macros and 50 prerequisite hashes; see MAILWRAPPER-QUALIFICATION.md. The next
reviewed component, dtracedctl, now qualifies plain/full-LTO builds with actual
WARNS=3 macro/header/link-tool policy, ten exact installation records, matching
runtime sections and six safe pre-connect test methods per profile. Genuine
linked bitcode is captured; only three DWARF sections differ. Installed daemon
protocol/runtime remains open. See DTRACEDCTL-QUALIFICATION.md. This component
result does not establish completion of the remaining inventory.

Parent-export review found no directory-specific exports/SUBDIR_ENV in
usr.sbin/Makefile, usr.sbin/Makefile.inc or base-accounts/test Makefiles. The
maintained world traversal uses real Make buildenv; broader per-directory
export/action completeness remains a review gate. The separate module inventory
correction is not evidence that these world observations establish complete
action or source coverage.

## Completion gates

Continue with independently built Make references and immutable native artifact
captures per cohort, preserving explicit options, generated inputs, DTrace/FIDL,
audit integration, literal non-ELF payloads and package ownership. Reconcile
actual native targets and installed records to the full selected inventory.
Then build maintained world/kernel/install aggregates, native pkgbase creation,
hardware integration and verified combined publication. Full boot, login/PAM/su,
SSH and service tests, cache/configuration checks and controlled CPU, memory and
disk-I/O/disk-use measurements remain required before claiming completion.

Existing format-5 component qualification and the read-only maintained inventory
APIs cover this refresh without frontend C/backend changes. Resource reserves
must remain enforced; no receipt/evidence, boot environment or snapshot was
deleted by this userland work to make a test pass.
