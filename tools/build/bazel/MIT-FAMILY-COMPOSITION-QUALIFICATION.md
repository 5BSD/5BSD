# MIT Kerberos production composition (2026-11-05)

## Implementation and selected build

The source-owned MIT parent now exposes production_products and
production_installation_archives. It includes 43 existing installation archive
contributions and both regular and PIE variants of five internal libraries:
apputils, kadmin_common, kprop_util, profile and ss. The ten internal archives
are build outputs, not invented installed payloads. Independent recursive Make
queries select 48 corresponding owners across 57 directories, with no missing
or extra native owner in this configured AMD64 profile.

The profile library now supplies its original PIE variant. Production PIE
consumers select that variant. Original Make compile records put -fPIC after
-fpie for this particular library; the native flags preserve that order. Its
original Makefile has no LIBADD. The native library therefore declares its
compile headers without exporting unrelated shared-library link dependencies.
Callers retain their own explicit link closure.

An intermediate combined build passed its selected tests but failed the strict
original ELF comparison: gssd acquired a direct libcom_err dependency through
the profile library. Removing that incorrect dependency export fixes the actual
build graph. Neither linker suppression flags nor relaxed comparisons are used.
The final gssd and krb5kdc component comparisons pass complete logical metadata,
manual payloads, ordered dynamic dependencies, interfaces, hardening and debug
CRC checks. Original link records prove use of the actual original profile PIE
archive. Other original link libraries use prepared original build/SDK inputs;
this is not a fresh whole-world Make comparison.

## Retained evidence under /usr/obj/usr/src

- bazel-mit-parent-native-r1-20261105: standalone MIT construction passes 19
  selected test targets. The parent captures 43 installation contributions and
  ten internal archives. Local tests cover support, crypto, principals, GSS
  sequence state, profile, error tables, verto and date parsing/settings.
- bazel-nine-families-native-r3-20261105: final maintained build-bsd request,
  using all 16 logical CPUs, passes all 52 selected test targets across the
  nine composed families. This is an unsigned AMD64 qualification profile with
  NIS, sendmail, printing, FDT, bootparamd and legacy updater explicitly enabled;
  installed tests are disabled and tests_support/Kerberos support enabled.
- bazel-nine-families-namespace-r3-20261105/review.json: all captured
  archive/request bindings reconcile to 1114 unique installation archives and
  23350 distinct non-directory destinations, with zero conflicting file claims.
  Repeated selections of identical archives are reconciled; directory ownership,
  original payload equivalence and pkgbase acceptance are separate gates.
- bazel-mit-selection-r2-20261105/review.json: current source-bound original
  Make recursive inventory and actual configured native owner query agree on
  all 48 owners. This checks selected ownership, not every artifact's parity.
- bazel-mit-profile-make-r3-20261105 and bazel-mit-ss-make-r1-20261105:
  complete original component installations are empty. INTERNALLIB suppresses
  header/library installation; bsd.lib.mk does not install the parsed ss SCRIPTS.
  The public profile header is owned by krb5/include instead.
- The final native run's profile-original-review/review.json compares both
  profile archives with the current original reference: member order and symbols
  agree. Public profile.h differs in exactly one generated filename comment:
  Make emits et-h-prof_err.h; native generation emits its Bazel output path.
  All other header bytes agree. The raw difference is retained; output is not
  rewritten and byte identity is not claimed.
- bazel-mit-profile-standard-make-r2-20261105/receipt.json binds the actual
  original internal archive at its standard /usr/obj build location. No verified
  SDK overlay, relocated link substitute or source-layout bypass is used.
- The final native run's changed-program-original-review/review.json records
  the complete gssd/KDC component, ELF/debug and original PIE-link comparisons.
- Its prior-nine-family-differences.json compares all 2916 production-installation
  output entries shared with the initial nine-family run. Only the bsd-build
  manual archive changes; the final corrected gssd/KDC payloads match that first
  run. The intermediate r2 ELF failure remains rejected evidence.

## Frontend, instrumentation and remaining work

The maintained format-5 frontend already accepts these native targets and source
settings. Its manual now describes internal products, PIE consumers and test
scope; no new dispatcher/schema, staging, signing or publication change is
required. Original application sources and instrumentation are unchanged.

These local tests do not run a live KDC, credential lifecycle, network GSS/NFS,
login/PAM, SSH authentication or audit/probe delivery. Complete MIT installed
metadata/payload/tests/pkgbase parity, alternate Heimdal selection and other ABIs
remain open. Remaining world roots, kernel/module installation, independent
bootstrap, packages/hardware/publication, real system boot/runtime and controlled
CPU/RAM/disk I/O/footprint/cache/sandbox comparisons also remain required. Make
stays production/default. BIP is excluded. No host installation, upgrade or reboot
was performed. This milestone is not complete world or system acceptance.
