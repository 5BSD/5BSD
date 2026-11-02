# WPA private support libraries (2026-11-02)

## Source ownership

Nine additional private libraries have explicit native sources, observed
physical header owners and distinct ordinary/PIE object/archive variants:

| Directory | Library | C sources | Extra maintained selection |
| --- | --- | ---: | --- |
| eap_common | wpaeap_common | 9 | Common WPA crypto/EAPOL configuration |
| eapol_auth | wpaeapol_auth | 2 | Common WPA configuration |
| eapol_supp | wpaeapol_supp | 1 | IEEE8021X_EAPOL |
| l2_packet | wpal2_packet | 1 | IEEE8021X_EAPOL |
| radius | wparadius | 4 | CONFIG_IPV6 from MK_INET6 |
| rsn_supp | wparsn_supp | 6 | Common WPA configuration |
| drivers | wpadrivers | 4 | Original wired driver source list |
| pasn | wpapasn | 3 | Original PASN include root |
| wps | wpawps | 17 | CONFIG_IPV6 from MK_INET6 |

The 47 sources remain unchanged. The source-owned library.bzl family macro
composes supported rules_cc cc_library groups and the existing own-object
archive helper. Every caller maintains its actual ordered source list and
extra flags. It does not inspect Make or emit BUILD files during a build.
Existing utility/crypto/common library declarations are unchanged.
All configuration variants of each new library consume the same contributed
header set, so each has one explicit header provider. Qualified fst/fst.h
includes use the genuine src root; no extra fst include directory is invented.

## Qualification

All evidence paths below are relative to /usr/obj/usr/src.

- The resumed host/SDK baseline is retained in
  bazel-wpa-common-resume-sdk-validation-r1-20261102.json (16,812 checks pass).
  Source, execution and compiler input identities remain explicit; old receipts
  were not rebound after an upgrade.
- bazel-wpa-support-reference-matrix-20261102.json records 38 successful
  independent maintained Make references: all four OpenSSL/EAPOL combinations
  for each library, plus IPv6-disabled radius and WPS. Four independent jobs
  use four compilation workers each. The maintained helper and original
  Makefiles/configuration choose all options, archive contents and installation.
- bazel-wpa-support-recipe-capture-20261102/report.json records 418 actual
  ordinary/PIE compiler recipes through supported Make metadata. All original
  object bytes and prerequisite hashes remain unchanged. The complete command,
  object environment, metadata hashes and before/after input bindings are kept.
- Five normal build-bsd format-5 profiles
  bazel-wpa-support-<configuration>-qualification-r1-20261102 pass. Four select
  eighteen archive targets each; the IPv6-disabled profile selects four targets.
  All use sixteen jobs and the existing 18 GiB start / 16 GiB stop disk reserve.
  No reserve guard fired.
- bazel-wpa-support-archive-audit-20261102/report.json: all 76 immutable-capture
  archive comparisons preserve the actual Make member order and each member's
  defined/undefined symbols. All 38 independent component METALOGs are empty,
  as expected for these INTERNALLIBs. No runtime installation payload or new
  pkgbase package is fabricated for private archives.
- bazel-wpa-support-object-audit-20261102/report.json: each archive member is
  extracted from its receipt-bound immutable capture and its SHA matched to
  the actual CppCompile output digest. No mutable bazel-bin path is the oracle.
  All 418 object text sections and ordered decoded macro/warning vectors match
  the corresponding actual Make recipes. All 687 raw constant-data sections
  match. The 34,394 actual prerequisite checks, 237 unique physical source/
  sysroot files, match declared native action inputs.
- bazel-wpa-support-relocation-audit-20261102.json: all 94,261 raw non-debug
  relocation records match across 418 objects, including numeric symbol indices
  and addends. This comparison does not normalize source paths or rewrite
  artifacts. Complete debug/archive-file byte identity remains a separate gate.

The original macro order is preserved, including duplicate IEEE8021X_EAPOL
when the common and local Make configurations both add it. WARNS=0 retains
its genuine warnings rather than acquiring an invented Werror policy.
The first header-review draft incorrectly required every header parent to be
an include root; actual fst/fst.h prerequisites exposed that validation error.
It was corrected before any native invocation. The genuine source include
layout and compiler diagnostics were preserved. All five native profiles then
passed their first invocation.

## Frontend, observability and remaining gates

Existing typed format-5 openssl, wpa_supplicant_eapol and inet6 settings are the
normal maintained frontend API. There is no new build-bsd C/backend option,
SDK preparation, staging/signing/publication policy or package payload to add.
The existing WPA manual documentation covers these settings and native targets;
another cohort-only paragraph is unnecessary. Make remains production/default.

These archive-only profiles declare no runnable test targets. Their passing
receipts establish compile/object/archive comparisons, not authentication,
wired packet I/O, RADIUS, PASN, WPS, wireless or daemon event delivery. Runtime
coverage belongs with the completed consumers and disposable fixtures. The
source-bound instrumentation scan is recorded separately in
bazel-wpa-support-observability-20261102.json; shared kernel/library probes and
service logging still require actual event-delivery qualification.

Together with the preceding tranches, twelve of the sixteen WPA private
library directories now have bounded native output qualification, and two of
five WPA programs are qualified within their documented runtime scope.
The remaining private libraries are ap, eap_peer, eap_server and tls; remaining
programs are wpa_supplicant, wpa_cli and hostapd. Cross-userland, full WPA runtime,
complete pkgbase dependency/archive construction, full system builds/boot and
controlled cache/performance gates remain open. Build timing/action records
are retained observations, not performance comparisons or whole-system proof.
