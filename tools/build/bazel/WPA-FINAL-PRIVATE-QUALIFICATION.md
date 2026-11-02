# WPA AP, EAP and TLS private libraries — 2026-11-02

## Native ownership

The remaining four private library directories, ap, eap_peer, eap_server and
tls, now use the existing source-owned wpa_private_library macro. Ordinary
and PIE cc_library object groups retain Make's actual flags and ordered own
objects in native archives. The production graph does not interpret Make.

The declared source union is 92 C files. AP selects its three genuine EAPOL
sources and corresponding physical header context; EAP peer and server retain
their explicit original lists. TLS retains tlsv1_server.c with OpenSSL and adds
sixteen sources with the internal crypto implementation. Its libtommath.c is
an actual textual prerequisite of bignum.c, declared as an internal context
input rather than an invented separately compiled object. TLS_FUNCS is set by
the maintained Make configuration; no redundant public option was invented.
The duplicated common/local crypto and IEEE8021X macro flags remain ordered.

The independent Make review found eap_methods.c listed twice in eap_peer's
SRCS. The separate correction 87cc2e56b07 removes only the second entry; see
[the duplicate archive audit](WPA-EAP-PEER-DUPLICATE.md). The eight original
archives and failed duplicate contract remain preserved. All current EAP peer
comparisons use fresh corrected r2 references, never the stale r1 receipts.

## Performed checks

Evidence is retained under /usr/obj/usr/src:

- bazel-wpa-final-private-selected-references-20261102.json identifies all
  sixteen independently built Make references and their receipt hashes.
  The recipe-capture report records 660 actual compiler recipes through
  supported Make meta mode, with unchanged object and prerequisite hashes.
- Four normal build-bsd format-5 profiles select OpenSSL on/off crossed with
  EAPOL on/off, eight archive targets each. All pass with sixteen jobs and
  the existing 18 GiB start / 16 GiB stop guard; no guard fired. No executable
  test is fabricated for these private archives.
- bazel-wpa-final-private-archive-audit-20261102/report.json passes all 32
  immutable archive member-order and per-member defined/undefined symbol
  comparisons. All sixteen private component METALOGs are empty, matching
  INTERNALLIB ownership; no installed library or pkgbase package is invented.
- bazel-wpa-final-private-object-audit-20261102/report.json extracts each
  member from the receipt-bound capture and verifies its SHA against its
  actual CppCompile output. All 660 text sections and decoded ordered macro/
  warning vectors match Make. All 1,096 raw constant sections match. All
  59,912 actual prerequisite hash checks, 321 unique physical source/sysroot
  inputs, match the declared native action inputs, including libtommath.c.
- bazel-wpa-final-private-relocation-audit-20261102.json passes 145,996 raw
  non-debug relocation records across all 660 objects, including numeric
  symbol indices and addends. Artifacts are not rewritten or normalized.

All 660 reviewed compiler records report processwrapper-sandbox and
cache_hit=false. Execution logs range from 219,648,920 to 276,646,380 bytes;
these retained observations establish neither a controlled cache comparison
nor performance qualification. Complete archive/debug byte identity remains
a separate gate from the explicitly checked code/constants/relocations.

## Frontend, instrumentation and remaining work

The existing typed openssl and wpa_supplicant_eapol settings and explicit
format-5 target inputs cover the normal maintained build-bsd workflow. No new
frontend C/backend/API, SDK/staging/signing/publication policy or install payload
is introduced. Existing manual documentation covers these inputs; another
cohort-only paragraph is unnecessary. Make remains production/default.

The source-bound marker scan in bazel-wpa-final-private-observability-20261102.json
finds no recognized direct SDT/DTrace/audit/FIDL call markers in these 92 source
files. This does not establish shared instrumentation or runtime event delivery.
No production source body, probe, test or authentication policy was disabled.

All sixteen private WPA library directories now have bounded native output
qualification. Two of five WPA programs have their documented safe runtime
checks; wpa_cli, hostapd and wpa_supplicant remain to be converted and qualified.
Private library output checks do not prove authentication, TLS interoperability,
wireless operation, service control, complete pkgbase dependencies, cross-userland,
full system builds/boot or controlled performance. Those gates remain open.
