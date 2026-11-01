# Native mailwrapper qualification

2026-11-01. The source-owned candidate preserves the existing program and
option-dependent configuration/symlink/package graph. All ten configuration comparisons pass: 84 unique installation records,
literal payloads, aliases and eight actual installed GNU debug-link CRC checks.
All four program-present states match Make ELF/dependency/hardening contracts
and NEEDED order; only seven DWARF sections differ. Four real unprivileged
private-configuration tests pass after the compile-policy correction. Make
remains production/default; full system/MTA qualification is still open.

## Ownership and option semantics

`usr.sbin/mailwrapper/BUILD.bazel` declares the actual single C translation
unit and private pathnames header with native rules_cc, libutil dependencies,
PIE and the maintained ordinary Clang warning/macro settings. It does not
interpret Make, import a generated BUILD graph or rewrite production sources.
The installation macro owns the actual manual/debug/configuration files,
MTA aliases, rmail link and sendmail example, with their source package tags.
No original test suite exists in this component; the new tests are native
Bazel tests and do not invent an installed Make test package.

The existing typed MAIL/DMAGENT/SENDMAIL/OPENSSL settings and the new typed
MAILWRAPPER setting express the actual src.opts.mk and component choices:
MAIL=no disables all three mail selections; OPENSSL=no disables DMAGENT.
The wrapper receives the DMA configuration when DMA is enabled or sendmail
is disabled, including the no-agent default. Otherwise it receives the
original sendmail configuration. Without the wrapper, its installed symlink
selects DMA first, then sendmail; no selections installs no component payload.
MTA aliases, rmail and the example retain their actual individual conditions.

The shared `dmagent_enabled` selector has an additional CRYPT requirement
which is absent from these actual Make conditions. This tranche leaves that
selector unchanged and does not use it to decide mailwrapper installation.
Reconcile that separate selector against DMA's full source/build dependencies
before claiming complete configured-world policy parity.

Make emits `/etc/mail` twice through install and installconfig. The audit
retains that provenance, requires identical metadata for repeats and only
then compares the unique paths with the native manifest. Different repeated
metadata is a failure. Every non-directory tar member must be an expected
component path; empty states must not hide binary/configuration payloads.

## Runtime scope

Four native tests use the existing unprivileged LOCALBASE interface with an
existing private mailer.conf and a declared native echo helper. They verify
actual program-name dispatch and argument order, unmatched mappings, malformed
mappings and explicit exec failure, including expected exit codes/stdout/stderr.
No test enters host /etc/mail, default-MTA fallback, mail queues or a running
mail service. Production paths and environment handling are unchanged; no
new fixture-only runtime API was added. Privileged/default-path fallback,
actual DMA/sendmail delivery and syslog consumer integration remain guest or
service qualification gates.

## Evidence and corrected gates

All paths below are under `/usr/obj/usr/src`:

- `bazel-mailwrapper-make-matrix-20261101.json`: ten maintained independent
  Make references, all passing: eight wrapper/DMA/sendmail selections plus
  MAIL-off and OPENSSL-off dependency edges;
- `bazel-mailwrapper-qualification-r1-20261101`: first default native capture
  and four passing dispatch/error tests;
- `bazel-mailwrapper-elf-r1-20261101.json`: matching ELF/dependency/hardening
  contracts and exact NEEDED order; only seven DWARF sections differ;
- `bazel-mailwrapper-default-install-audit-r1-20261101/report.json`: thirteen
  unique default installation records, literal manual/config bytes, and both
  actual installed GNU debug-link CRCs passing;
- `bazel-mailwrapper-native-matrix-20261101.out`: preserved first matrix and
  its strict source-hash rejection on the later MAIL-off reference;
- `bazel-mailwrapper-reference-refresh-result-20261101.json`: fresh independent
  dependency-edge references after the declaration freeze. The original
  receipts captured a then-changing BUILD file and were not silently rebound.

The first native declaration omitted Make's explicit -DPIC and warning vector.
Its runtime sections matched Make, but that does not establish compile-policy
parity. The source-owned declaration now retains those actual macros,
-pipe/-fno-common/-Qunused-arguments and the ordered maintained warnings,
including original diagnostic exceptions and the existing typed WERROR flag.
Fresh affected native binary/default-test captures pass; the initial binary
gate is superseded for compile-policy claims. The actual corrected default
compile action has exactly the 29 ordered Make warning flags, ten required
macro/optimization/debug/stack-protector settings, and all 50 Make prerequisite
hashes represented in its declared native inputs. This is an input/command
audit, not a syscall read trace or a claim that all declared SDK headers were
consumed. No shared toolchain or
previously converted programs were silently changed. Warning-policy
reconciliation across earlier userland components remains an explicit
whole-system completion gate, even where ELF/runtime comparisons passed.

Final evidence:

- `bazel-mailwrapper-corrected-native-result-20261101.json`: all six final
  native profiles pass, including the corrected default runtime-test gate;
- `bazel-mailwrapper-final-audit-result-20261101.json`: all ten configuration
  bindings and 84 exact component records. Its per-state `report.json` files
  bind immutable archive/metadata captures and actual debug CRC checks;
- the corresponding `elf.json` files under each program-present state's
  `bazel-mailwrapper-STATE-final-audit-20261101` directory: full ELF contract,
  exact NEEDED order and the seven recorded DWARF differences;
- `bazel-mailwrapper-compile-audit-20261101.json`: actual corrected compiler
  command, exact ordered warnings, macro/settings and 50 Make input hashes.

The final four binary-present and two dependency-edge captures use r2. The
four binary-absent principal selections use their passing r1 captures; their
metadata actions do not consume the corrected compiler options. Both empty
states have no unexpected non-directory archive members. The source Make
program and all production configuration/manual bytes remain unchanged.

The normal `build-bsd bazel-test --bazel-inputs ... --jobs 16` entry point uses
format-5 typed build-setting labels. No frontend C option, backend bypass,
shared runtime API, host installation or publication was added. Disk guards
retain an 18 GiB minimum start and 16 GiB reserve. Current evidence is a
native amd64 component qualification effort, not complete userland/world,
pkgbase creation, MTA installation, cross-userland or controlled performance
acceptance.
