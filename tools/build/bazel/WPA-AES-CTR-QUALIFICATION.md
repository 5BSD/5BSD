# WPA AES-SIV dependency correction — 2026-11-02

The OpenSSL private crypto archive always selects aes-siv.c, which calls
`aes_ctr_encrypt`. Makefile.crypto previously requested aes-ctr.c only through
the optional EAPOL/EAX group. A fresh independent hostapd build with OpenSSL and
WITHOUT_WPA_SUPPLICANT_EAPOL failed to link that missing symbol. The original
failure remains in bazel-wpa-hostapd-openssl-noeapol-make-r1-20261102 under
/usr/obj/usr/src.

The correction requests NEED_AES_CTR in the OpenSSL branch. The native source
list expresses the same existing OpenSSL-or-EAPOL condition with the pinned
bazel_skylib selects.with_or API. CTR keeps its original archive position and
appears once when both conditions are true. No source bodies, public feature
macros, compiler policy, backend, SDK or frontend API are changed.

## Evidence

All evidence paths below are relative to /usr/obj/usr/src.

- bazel-wpa-aes-ctr-evidence-20261102/metadata-comparison.json checks 84 component/
  configuration descriptions and 1,008 fields. Exactly one field changes:
  src/crypto's OpenSSL/no-EAPOL source list gains aes-ctr.c. All other inspected
  source lists, macro/compiler flags, library selections, search paths and
  target identities remain unchanged.
- Four fresh independent maintained Make crypto builds produce ordinary and PIE
  archives with 19/17 OpenSSL sources and 39/36 internal-backend sources for
  EAPOL enabled/disabled. Supported Make metadata captures all 222 actual
  compiler recipes without changing object bytes. The earlier 19/16 OpenSSL
  count in historical documents describes the pre-correction implementation.
- bazel-wpa-aes-ctr-evidence-20261102/preexisting-code-comparison.json verifies
  all 70 preexisting members of the two OpenSSL configurations: allocated code/
  data and raw nondebug relocations remain unchanged. Only the missing CTR
  object is added to the no-EAPOL archives.
- Four normal build-bsd format-5 configurations with sixteen jobs and the
  existing 18 GiB start / 16 GiB stop reserve pass. The archive audit passes all
  eight immutable captures' exact member order, duplicate rejection and defined/
  undefined symbol contracts against the fresh Make archives.
- bazel-wpa-aes-ctr-crypto-object-audit-r3-20261102/report.json binds all 222
  immutable archive members to actual compiler output hashes and checks ordered
  macro/warning policy plus 17,600 physical prerequisite hashes (254 unique). All
  text sections match. Of 180 raw constant sections, 172 match exactly; all eight
  differences are whole string sections explained by one verified diagnostic
  /usr/src/ prefix expansion, with original bytes retained. The strict raw
  relocation check rejects six objects; 216 match exactly. The difference report
  and filename proof remain separate, with no full relocation/ABI parity claim.
- Both fresh Make hostapd consumers now link, including the previously failing
  OpenSSL/no-EAPOL case. Their native builds, package installation manifests and
  safe CLI/loader reports pass (eight real methods, two Bazel wrappers; default
  report cached). These branches do not initialize drivers or an access point.

The native matrix summary initially reused a local variable for provisional
snapshots. The malformed summary and executed script are retained as
bazel-wpa-aes-ctr-crypto-native-matrix-invalid-snapshot-shadowing-20261102.json
and bazel-wpa-aes-ctr-crypto-native-matrix-executed-20261102.py. The corrected
summary is reconstructed from the four independently completed guard records
and qualification receipts, verifying exit status, exact inputs/output arguments,
receipt status and hashes. No build receipt or captured output is rewritten.

Default outputs were cached, including the default hostapd safe-test report.
Current immutable archive bytes equal the earlier execution-bound archives.
Compiler provenance comes from the actual earlier executed qualification,
not a later cached log with no matching actions. Rejected provenance attempts
remain preserved; cached reports are not additional compiler/test executions.

## Remaining gates

This fixes the demonstrated OpenSSL dependency. Existing hostapd builds without
OpenSSL still fail independently in maintained Make because enabled SAE/EHT and
other features require APIs the selected internal crypto backend does not
provide. Those failures remain explicit; no feature is silently disabled.
Complete backend feature/API closure, service/authentication/wireless runtime,
whole-system/pkgbase and cross-userland qualification remain open.

Existing typed openssl/wpa_supplicant_eapol settings and targets cover the normal
build-bsd workflow. No frontend C, staging, signing, verification, publication or
manual option changes are needed. Make remains production/default.
