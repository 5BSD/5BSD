# WPA common library and hostapd control client

## Maintained native ownership (2026-11-02)

The common library now declares its eleven original C sources, exact physical
header contexts, ordinary/PIE object groups and private archives. The one-source
hostapd_cli program declares its original SSL/crypto/util/common/utils link
selection, manual/debug installation in pkgbase's hostapd package, and safe CLI
and loader tests. Checked-in common/version.h remains the version input; no
constant or generated replacement was invented. There is no production Make
interpretation, hidden host library search or imported object fallback.

The existing format-5 build-bsd target/settings API covers this tranche without
new CLI, backend or staging/security policy. Existing openssl and
wpa_supplicant_eapol settings preserve all four Make configurations. The common
header prerequisite set is identical across them, so one explicit source-owned
provider suffices. Make remains production/default; private archives are not
runtime package payloads. This follows WPA-PRIVATE-QUALIFICATION.md rather than
qualifying the remaining WPA libraries, supplicant or hostapd daemon.

## Retained checks

Paths below are under /usr/obj/usr/src.

- Resume SDK validation bazel-wpa-common-resume-sdk-validation-r1-20261102.json:
  16,812 input hashes pass against the existing immutable post-upgrade receipt.
  Host remains hypertrace 40ea99e869b4. No SDK receipt was rebound. Saved Make
  reference validation records 432 source/compiler/profile/program/archive
  checks, with zero mismatches. The common source recipes are separately bound
  through actual metadata and current declared prerequisite comparisons.
- Independent common Make references cover openssl-eapol, openssl-noeapol,
  internal-eapol and internal-noeapol. Their four corresponding control-client
  references explicitly select the fresh common and utility PIE archives in
  DPADD, LDADD and the actual Make link. Full invocations and hashes are in
  bazel-wpa-{common,hostapd-cli}-<configuration>-make-r1-20261102. The maintained
  reference helper's arbitrary-variable policy was not expanded.
- Four normal frontend receipts bazel-wpa-common-<configuration>-qualification-r1-20261102
  pass (the first configuration is named default). All builds use 16 jobs and
  the existing 18 GiB start / 16 GiB stop reserve; no reserve guard fired.
- bazel-wpa-common-elf-audit-r2-20261102/report.json: twelve immutable-capture
  comparisons pass: eight archives retain ordered members and per-member
  symbols; four programs retain strict ELF/interpreter/PIE, ordered NEEDED,
  hardening and versioned dynamic-symbol contracts against Make.
- bazel-wpa-common-default-object-audit-20261102/report.json: all 23 default
  actual compiler actions (11 ordinary + 11 PIE + client) preserve raw text
  bytes and ordered decoded macro/warning vectors. Make's repeated program
  configuration is retained. Ordinary and PIE flags remain distinct.
- bazel-wpa-common-header-audit-20261102.json: 1,803 Make prerequisite hash
  checks, 121 unique source/sysroot files, match the declared native inputs.
- All 41 raw-object constant-data sections match exactly. All 9,916 non-debug
  relocations match offset/type/target symbol/addend, excluding numeric symbol
  indices/placement. See bazel-wpa-common-{rodata,relocation}-audit-r1-20261102.
- Actual digest-bound default linker arguments preserve Make's explicit order:
  ssl, crypto, util, wpacommon_pie, wpautils_pie. See
  bazel-wpa-common-link-order-20261102.json.
- bazel-wpa-common-install-audit-20261102/report.json: all five installed file/
  directory records preserve owners/groups/modes/package tags, manual payloads
  match after decompression, and both native and Make debug-link CRCs validate.
  The independent Make installation is under its own staging root, not the host.
- All four native logs report four actual unittest methods: sixteen executions,
  versus one XML Python wrapper per profile. Cases check help, version, invalid
  options and actual rtld resolution from declared native directories. Source
  review establishes these CLI branches return before daemon connection.
  The same cases pass against Make. No host service/device/network configuration
  or tracing activation is performed. These tests do not cover control requests,
  daemon authentication/events, wireless operation or full OS startup.

## Differences and open gates

Final ELF/debug bytes are not identical. The final section reports retain the
actual debug, address/symbol-table, relocation and constant-data differences;
these are not waived as a blanket source-path explanation. Direct final-rodata
review identifies inherited utility eloop's relative versus /usr/src-prefixed
filename at different string-pool placements. The final image also contains
linker-resolved tables/fixups with differing addresses/layout. New raw common/
client text, constants, symbolic relocations and explicit link order have the
scoped comparisons above; complete linked-image/ABI equivalence is not claimed.
The inherited utility filename difference is recorded in the prior tranche.

The first new Make test run rejected an incorrect single-line version
expectation: upstream's version output includes a copyright line. The test was
corrected from the original source; production output was not altered. Earlier
partial audit reports and observation-script failures are retained separately;
the complete twelve-comparison report is r2. The action audit verifies the
54,519,572-byte default execution log SHA and 33 actual object/parameter/output
snapshot bindings. Its sole unmatched program runfiles alias is separately
bound to the immutable program hash. No tool-bootstrap actions occurred in that
warm profile; this does not establish a general cache or performance result.

No direct SDT/DTrace, FIDL or BSM audit markers occur in the twelve selected
source files (bazel-wpa-common-observability-20261102.json). Review shared event
coverage and actual daemon/security delivery as the rest of WPA is migrated.
Remaining private libraries/programs, cross-userland builds, other man/split-man
configurations, actual pkgbase archive/dependency construction, complete system
boot and controlled performance remain open. Native declarations are maintained
source, not a claim of whole-family or whole-system completion.
