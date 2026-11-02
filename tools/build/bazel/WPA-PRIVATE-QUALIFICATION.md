# WPA private libraries and passphrase qualification

## Scope (2026-11-02)

Native rules_cc owns `wpautils` (12 C sources), `wpacrypto` (19/16 C sources
with OpenSSL, 39/36 with internal crypto, according to EAPOL), their distinct
ordinary and PIE archives, and the one-source `wpa_passphrase` program. Original
source files and source-owned physical header contexts are declared explicitly.
There is no production Make query, generated BUILD replacement, host object
import, or compiler fallback. Make remains the production/default system build.
The remaining WPA libraries, hostapd, supplicant, control clients and their
wireless/service runtime are still open migration gates.

The existing typed format-5 build input API accepts the maintained `openssl`,
new `wpa_supplicant_eapol`, and new `inet6` settings under
`//tools/build/bazel/config`. Defaults match the reviewed Make configuration.
`inet6` models MK_INET6, separately from the existing MK_INET6_SUPPORT setting.
Normal `build-bsd bazel-test --bazel-inputs ... --output ... --jobs 16` executes
this graph. No new frontend C option, staging/signing policy or backend is
required. Private archives have no runtime package payload; program/manual/debug
installation belongs to pkgbase's `wpa` package.

## Verified outputs and tests

All evidence paths below are relative to `/usr/obj/usr/src`.

- Fresh post-upgrade SDK: `bazel-postupgrade-sdk-20261102`; receipt SHA256
  `c35e046fc3ae5a66e1355c83ac8d3cca7a428b126c5a1767a27da1df30956013`.
  The parent's maintained preparation validates 16,812 inputs. Historical SDK
  host-input mismatches remain recorded; old receipts were not rebound.
- Default independent Make references: `bazel-wpa-{utils,crypto}-make-r1-20261102`.
  Actual per-object recipes are retained by
  `bazel-wpa-private-recipe-capture-20261102/report.json`; metadata capture
  leaves all 62 ordinary/PIE object hashes unchanged.
- `bazel-wpa-passphrase-make-r1-20261102` records complete Make commands,
  source/compiler/archive hashes, DPADD, LDADD and actual linker selection of
  those fresh private PIE archives. This specific independent reference uses
  documented library directory/archive assignments; the production reference
  helper's arbitrary-variable gate was not widened.
- Final default native receipt: `bazel-wpa-default-qualification-r4-20261102`.
  Four additional receipts `bazel-wpa-<name>-qualification-r1-20261102` cover
  `openssl-noeapol`, `internal-eapol`, `internal-noeapol`, and
  `openssl-eapol-noinet6`. Each builds four archives, the program, its install
  archive, and its declared Python test. All five receipts pass.
- `bazel-wpa-all-elf-audit-20261102/report.json`: 25 immutable-capture comparisons
  pass: ordered archive members and per-member symbols for 20 archives, and
  strict ELF/PIE/interpreter, ordered NEEDED, dynamic symbols/version requirements
  and hardening contracts for five programs. Option-specific Make references
  are fresh; INET6-off uses its own utility reference and unchanged crypto/program
  products. This does not establish byte-identical final ELF/debug output.
- Default `bazel-wpa-default-object-audit-20261102/report.json`: all 63 actual C
  actions have exact raw `.text`, ordered decoded macro values and warning
  vectors against actual Make recipes. Ordinary and PIE compilation are
  distinct. Make's genuine duplicate program macro/warning group is preserved;
  WARNS=0 does not acquire an invented global Werror policy.
- `bazel-wpa-header-audit-20261102.json`: 5,229 actual Make prerequisite hashes,
  247 unique source/sysroot files, match each native action's declared inputs.
- `bazel-wpa-rodata-audit-r2-20261102/report.json`: 60 of 66 constant-data
  sections match exactly. The other six contain the original `__FILE__` values
  in ordinary/PIE eloop, crypto_openssl and tls_openssl. Native spelling is the
  stable relative source path; Make prepends `/usr/src/`. Removing only that
  observed prefix produces identical bytes. No absolute build path is embedded
  to force a comparison pass.
- `bazel-wpa-relocation-audit-r2-20261102.json`: all 10,678 non-debug relocations
  across 63 objects preserve offset/type/symbol/addend, with 96 changed string
  offsets resolved to their actual identical strings or the observed original
  source-filename literals. Numeric symbol indices/placement are not compared.
  This explains source-constant placement changes; full final-image byte/debug
  parity and full ABI equivalence are not claimed.
- `bazel-wpa-install-audit-20261102/report.json`: actual independent Make install
  versus final captured native archive: all five paths/types/owners/groups/modes/
  pkgbase tags match, decompressed manual bytes match, and both native and Make
  debug-link CRCs validate. Binary/debug bytes have the documented differences.
- Each of five native test logs contains seven actual unittest methods (35
  executions total); Bazel XML accurately reports one Python wrapper per profile.
  Cases cover argv/pipe key derivation, pipe EOF, PTY echo enabled/disabled,
  PTY EOF echo restoration, and actual rtld resolution restricted to declared
  native library directories. No host account, clock, wireless or tracing state
  is changed. The inherited interpreter/kernel remain host execution inputs;
  this is not a whole-system boot test.

The source termios fix is the separate commit `6c06060029c`; see
WPA-STDIN-FIX-QUALIFICATION.md. Its original-source negative fails the PTY EOF
restoration assertion. `bazel-wpa-runtime-negative-r2-20261102.json` proves the
new loader assertion rejects host libthr fallback when native libthr is omitted.

## Retained failures and evidence limits

The first native default run failed because a string macro lost quoting in
copts tokenization; the maintained literal now preserves the original cipher
value. The first successful six-method test lacked an explicit native libthr
runtime edge. Final declarations add it, and final seven-method tests inspect
actual rtld choices. Earlier success does not establish that earlier closure.
The final five default compiled artifacts are hash-identical in immutable
r2/r3/r4 captures (`bazel-wpa-default-capture-equality-20261102.json`).
The complete r2 execution log SHA is verified by the streaming
`bazel-wpa-default-execution-audit-r2-20261102/report.json`; actual compile/output
bindings validate the later snapshot rather than trusting mutable bazel-bin.
Initial observation-script failures and the incomplete relocation diagnostic are
retained; only the explicitly completed r2 relocation report is authoritative.

The expanded default execution log is about 9.1 GiB. Its real exec dependency
chain includes native DTrace/dtotel/OpenTelemetry/protobuf/Abseil through libutil's
section provider. Prepared tools use the same output-root namespace as earlier
SDKs; no namespace-change or needless-rebuild claim follows from progress counts.
Compact maintained logging and exec-cache/resource qualification remain full-build
completion gates. Disk guards use an 18 GiB initial reserve and 16 GiB stop floor;
none fired. Timing and disk samples are observations, not controlled performance
comparisons.

No DTrace SDT schemas, FIDL generation or BSM audit calls are present in this
selected source closure. Their absence is recorded, not repaired by invented
probes. Remaining WPA network/security behavior, cross-userland builds, full
MAN/MANCOMPRESS/split-man configurations, native pkg archive creation/dependencies,
full-system boot and performance remain unqualified.
