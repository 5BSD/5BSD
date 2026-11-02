# Duplicate EAP peer source entry (2026-11-02)

The original usr.sbin/wpa/src/eap_peer/Makefile lists eap_methods.c twice.
Independent Make builds confirm both ordinary and PIE archives contain fifteen
members, including two eap_methods object entries, in all four OpenSSL/EAPOL
configurations. The duplicated entries contain identical bytes. This is an
actual Make product issue, rather than a native declaration normalization.

The correction removes only the second source-list occurrence after eap_wsc.c.
The first entry and the relative order of all other sources remain unchanged.
No contributed C source, feature flag, compiler policy or public installation
payload changes. These archives are private INTERNALLIB products.

Evidence under /usr/obj/usr/src:

- bazel-wpa-eap-peer-duplicate-evidence-20261102/report.json binds all eight
  original archive hashes and member orders. The two instances are extracted
  separately with llvm-ar xN and each matches the original compiled object SHA.
  Makefile.before is the exact source before-image and matches the old four
  reference receipts. Original archives and receipts are preserved unchanged.
- bazel-wpa-final-private-eap_peer-<configuration>-make-r1-20261102 retains the
  original successful Make references. Their source Makefile hash intentionally
  differs after this correction; they are historical evidence, not the current
  build baseline.
- bazel-wpa-eap-peer-corrected-reference-matrix-20261102.json records four fresh
  successful Make configurations, using the maintained reference helper and four
  compilation workers per independent build. Outputs use make-r2 directories.
- bazel-wpa-eap-peer-correction-audit-20261102.json validates all eight corrected
  archives have exactly fourteen distinct ordered members. The only order change
  is removal of the second identical entry. All 112 unique object comparisons
  (14 members x ordinary/PIE x four configurations) retain every non-debug ELF
  section byte, including text, constants, symbols and relocation contents.
  Full object debug bytes differ because independent object-root paths differ.
  All corrected component installation METALOGs remain empty.

No strict archive checker was relaxed and no duplicate was silently removed
from a native source inventory. Native EAP peer declarations and whole WPA
program/runtime qualification follow this separately verified Make correction.
The existing build-bsd/reference inputs and backend API are unchanged; no new
frontend option, SDK staging, signing or publication behavior is introduced.
