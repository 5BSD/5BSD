# Internal rescue replacement library (2026-11-02)

## Product and ownership contract

`//rescue/librescue:all_products` builds the seven original rescue replacement
sources as regular and PIE objects, and their two own-object archives. The
physical libc/gen, libc/net, libc/stdlib and libutil sources remain exported by
their existing owners only to this consumer. A narrow libc/include provider
supplies the four actual private headers and the ordinary libsys header view.

The two ordinary cc_library groups preserve original `RESCUE`, private database,
POSIX/DES/PORTMAP and selected INET6/YP/HESIOD macros, exact Make warnings,
C17/O2/debug policy and PIE's `-fpie -DPIC`. Existing `-bsd_ssp` feature exclusion
preserves Make's explicit `MK_SSP=no` without changing dependency/toolchain
policy. Existing typed inet6_support, nis and hesiod settings control the actual
Make conditions; no new flag, frontend field or arbitrary variable is added.

Make marks this library `INTERNALLIB`: it must not be installed. Native rules
therefore introduce no archive installation, directory, manifest or package
output. Public regular/PIE compiler-output collections expose the actual
objects, without archive extraction. This preserves the original rescue
consumer contract: rescue/rescue includes `../librescue/*.o` before ordinary
libraries so the replacements win. The full crunchgen program and its static
library/application closure remain a separate implementation and runtime gate.
This component does not claim a linked native rescue executable.

## Verified evidence

All evidence is under `/usr/obj/usr/src`. Passed payloads use the maintained
immutable target/output resolver with receipt/manifest/payload hash checks.

- `bazel-librescue-make-reference-r1-20261102`: original selected-world Make,
  supported `.meta` recipes, seven regular plus seven PIE objects, two archives,
  and genuinely empty component installation metadata. No host installation.
- `bazel-librescue-native-qualification-r2-20261102`: ordinary format-5
  build-only profile with the selected posttar SDK, 16 jobs and the established
  18 GiB start / 16 GiB reserve guard. All fourteen original compiler products
  and both archives build successfully; no test execution is claimed.
- `bazel-librescue-review-r3-20261102`: all fourteen object allocated sections
  match original Make exactly. Actual executed compiler warnings, feature
  macros, O2/debug and disabled SSP agree; all 816 consumed Make dependency
  occurrences match native source/header input hashes. Cached regular outputs
  bind to the retained original executed actions by exact output digest;
  corrected PIE outputs bind to the executed r2 actions.
- `bazel-librescue-features-make-reference-r2-20261102` and
  `bazel-librescue-features-native-qualification-r2-20261102`: independently
  built INET6_SUPPORT=no, NIS=yes, HESIOD=no control. The corresponding
  `bazel-librescue-features-review-r1-20261102` verifies fourteen more actual
  compiler actions, all allocated payloads, both archives and all 878 consumed
  dependency occurrences against that actual changed Make recipe.
- `bazel-librescue-relocations-review-r1-20261102`: all 28 compared objects
  preserve exact non-debug relocation-section bytes and every nm symbol record,
  in addition to allocated payload parity. No relocation/symbol normalization.
- `bazel-librescue-parent-reference-r2-20261102`: actual Makefile.inc1 world
  selection, rescue parent order (`librescue`, then `rescue`), child options and
  original own-object crunchgen consumption. This is parent-context metadata,
  not whole-world or rescue-executable compiled coverage.

The archives contain only the seven declared own objects, in the original Make
order. Native PIE members conventionally retain `.o`; Make names them `.pieo`.
The observer maps these explicit variant identities one-to-one and compares
untouched member allocated payloads, rather than renaming/repacking outputs or claiming
archive envelope/whole-file/debug-byte identity. Native archive filenames are
internal build products, with no installed-name contract.

## Retained failures and remaining scope

Initial native r1 built successfully but strict compiler-policy review rejected
its `-fPIE` spelling: Make actually uses `-fpie`. Only the source-owned PIE flag
was corrected and r2 rebuilt. The first feature Make control requested HESIOD
but the selected world SDK, prepared with HESIOD disabled, has no `hesiod.h`;
the original compiler fails before any native feature run. That failed reference
is retained in `bazel-librescue-features-make-reference-r1-20261102`. HESIOD-enabled
qualification requires a correctly prepared matching header/SDK configuration;
no host header fallback, silent SDK mutation or nominal variant pass is claimed.
The supported second feature control explicitly keeps HESIOD disabled.

Rejected observers for declared-original plus virtual-header views, PIE spelling,
and root Makefile versus Makefile.inc1 recursion are preserved with corrected
checks. `bazel-librescue-review-drivers-20261102` binds the retained scripts,
sources, reference receipts and final audit reports.

Original login_class source includes its logincap probe wrapper, but this rescue
recipe does not define WITH_DTRACE. That original disabled-probe policy is
preserved, not replaced by normal instrumented libutil objects. No credential,
login/session, command execution, sysctl or shell-list operation was run. Full
rescue generation/link/install/runtime, other configurations and architectures,
world aggregation, package creation and publication remain open. Existing
format-5/component/SDK providers suffice; no frontend C/backend/manual/security
or publication interface changed. Make remains production.
