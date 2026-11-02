# Native WPA family composition (2026-11-02)

## Source-owned products

The maintained usr.sbin/wpa/Makefile selects src, then wpa_supplicant, wpa_cli,
wpa_passphrase, hostapd and hostapd_cli. The native family owns those five programs
and both ordinary/PIE private archives for all sixteen src/Makefile directories
in their maintained order. Actual dependencies provide producer ordering;
Make's global .WAIT is not an artificial Bazel barrier. No Make interpretation,
generated production BUILD substitute or imported object fallback was added.
The package contexts for wpa and hostapd remain distinct.

The existing format-5 build-bsd targets/settings API directly builds all_products,
installation_archives and safe_tests. No CLI/backend/security change is required.
bsd_install_archive_set preserves each component's manifests and directory tags;
it does not claim to flatten a stage or produce final pkg archives. Make remains
production/default. No program code, compiler policy or installation policy was
changed by this aggregation; tests only add visibility for the parent suite.

## Retained qualification

All paths below are under /usr/obj/usr/src.

- bazel-wpa-family-default-qualification-r1-20261102 passes through the normal
  frontend with sixteen jobs, current explicit SDK, OpenSSL/EAPOL/IPv6/examples
  enabled and compact execution evidence. The 18 GiB start/16 GiB reserve guard
  did not fire. This is the default configuration, not a new all-backend claim.
- bazel-wpa-family-artifact-audit-r2-20261102/report.json binds all 37 products
  (32 private archives and five programs) and fifteen install outputs to valid
  prior immutable component captures or the independently repaired control-client
  proof. All payloads are byte-identical to their original qualified components.
  Its r1 attempt correctly failed when the historical default client capture
  failed its frozen hash; it is preserved, not counted as a passing comparison.
- Thirty-three install records preserve component owner/group/mode and package
  tags. The two shared debug directories each retain five component contexts,
  including both package=wpa and package=hostapd. They are not silently deduped
  into an ambiguous package owner. Final pkg creation/dependencies remain open.
- Five captured Python wrapper reports pass; their retained logs show 23 actual
  unittest methods (seven passphrase and four each for the other programs).
  These cover safe computation/error/CLI/loader paths; no daemon setup, WLAN,
  host service changes, tracing activation or authentication is performed.
- WPA-COMMON-CLIENT-QUALIFICATION.md explicitly invalidates the mutated historical
  default program capture and supersedes unsafe one-off section-inspection
  evidence. Fresh default Make library/client/install references and read-only
  object checks pass: 23 objects, 41 constants, 1,803 physical prerequisites,
  strict ELF, five records and both debug CRCs. Captured original files are not
  restored, renamed or rewritten to hide this failure.

## Remaining work

Internal crypto backend ECC/SAE/EHT failures remain actual Make/native closure
blockers; no features were disabled to pass. Preserve IPv6/examples-disabled
and custom-config tests, live control/driver/authentication/packet paths, audit
and DTrace/FIDL coverage review, final pkg creation, full-system boot and resource/
performance qualification as separate gates. This family milestone is not the
whole-world completion claim.

The fresh world inventory and metadata query cover 2,127 selected directories
(bazel-userland-world-inventory-r1-20261102 and world-components-r1-20261102).
world-native-survey-r1 records 1,447 local and 680 ancestor-only package-file
contexts. These are directory-presence review counts, not converted programs or
compiled coverage. Inherited parent exports and actual actions/generated outputs/
installation/pkg ownership still require reconciliation. The first concrete
next gap is lib/libxo/encoder/csv: csv.enc has a maintained Make source and install
selection but no native producer/install declaration. It must be checked under
its real parent context before conversion.
