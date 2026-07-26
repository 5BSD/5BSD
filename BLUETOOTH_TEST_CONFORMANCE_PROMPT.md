# Bluetooth test conformance and independent-oracle completion prompt

Act as a skeptical Bluetooth SIG specification, Mesh, FreeBSD kernel,
security, test-design, and C reviewer. Work directly in `/usr/src`. You are
authorized to improve tests and fix concrete defects they expose, but preserve
unrelated user changes in the dirty worktree. Do not claim “100%,” “no bugs,”
or Bluetooth qualification unless every applicable exit criterion below has
objective evidence.

## Normative inputs

- Use `/usr/src/bluetooth-specs/Core_Specification_6_3.pdf` and
  `Core_Specification_6_3.txt` as the Core 6.3 authority.
- Use the local adopted-profile, GATT Supplement, Mesh Protocol, Mesh Model,
  and Mesh profile documents for implemented profile and Mesh behavior.
- Use `/tmp/bluez` only as comparative implementation evidence. BlueZ source,
  FreeBSD production headers, existing tests, comments, and prior reports are
  never normative oracles.
- Record document name/version, volume, part, section, table/figure, and—when
  useful for locating text—PDF or extracted-text page for every claim.

## Non-negotiable oracle rule

Expected wire values, masks, UUIDs, sizes, error/status codes, cryptographic
vectors, state transitions, and boundary values must be independently
transcribed from a cited normative source into test-only oracle data. They may
not be imported, aliased, computed, `sizeof`-derived, or copied at runtime from
the production header/type/function being tested. Production symbols may
appear only on the actual side of a comparison.

Keep scalar wire oracles in
`tests/usr.sbin/bluetooth/blued/spec_oracles.h`, which must include no
production header. Keep larger byte strings/transcripts in test-only fixtures
with the citation adjacent to the data. A test that constructs both input and
expected output through the same production helper is self-referential and
does not count as normative coverage.

Use at least one of these independent techniques for behavioral requirements:

1. hand-encoded request and expected response bytes from the specification;
2. published SIG sample vectors/transcripts;
3. a deliberately separate reference implementation whose constants and
   algorithms do not include or call production code;
4. metamorphic/property assertions derived explicitly from a normative rule;
5. differential testing against BlueZ only as supplemental evidence, never as
   the sole normative oracle.

## Every-test reference rule

Inventory the exact output of `kyua list -k Kyuafile`. Give every generated
case one explicit traceability record—no implicit “all tests in this binary”
success claim. Each record must contain:

- exact Kyua case ID;
- `normative`, `implementation-contract`, or `mixed` authority;
- narrow normative citation(s), not a whole chapter such as “§§2–7”;
- requirement ID and precise behavior under test;
- oracle source and provenance (`SIG literal`, `SIG vector`, independent peer,
  state-machine property, or implementation contract);
- production entry points exercised;
- positive, boundary, malformed-input, state/error, and cleanup dimensions;
- status: verified, missing oracle, weak/self-referential, missing test, or
  environment-blocked.

Allocation-failure, logging, persistence-format, CLI, IPC, and internal
lifecycle tests that have no SIG requirement must cite their exact source/man
page/ABI implementation contract. Never attach a fake Bluetooth citation.
Mixed cases must record both authorities.

The traceability checker must reject an absent case, wildcard-only mapping,
non-narrow citation, missing provenance, missing requirement, duplicate case,
stale case, or normative value sourced from production code.

## Review and completion loop

Repeat this loop until a complete pass produces no new actionable gap:

1. Regenerate the exact Kyua inventory and compare it to traceability records.
2. Select one protocol slice: HCI, L2CAP, ATT, GATT/EATT, SMP, privacy,
   advertising, ISO, profiles, Mesh protocol, Mesh models, daemon IPC,
   persistence, or kernel sockets.
3. Read the applicable normative clauses before reading expected values in
   implementation headers or existing tests.
4. Enumerate every implemented requirement, field, bit, enum, bound, state,
   timer, error, and cleanup outcome in that slice.
5. Identify missing cases and weak/self-referential oracles. Write or repair
   tests immediately, with exact adjacent citations.
6. Use mutation checks: temporarily perturb the production constant/branch in
   an isolated patch or object tree and prove the relevant test fails for the
   intended reason; restore the mutation and verify the worktree exactly.
7. Run the narrow test, the traceability/oracle gates, strict builds, and the
   entire Kyua suite. Diagnose every unexpected skip.
8. Re-read the next specification slice and repeat. A green suite alone is not
   a stopping condition.

Also run sanitizers, static analysis, fuzz targets, and LLVM coverage where
supported. Coverage percentages help find unexecuted implementation code but
do not substitute for requirement or oracle coverage.

## Minimum verification commands

```sh
cd /usr/src/tests/usr.sbin/bluetooth/blued
make spec-traceability
make -j$(sysctl -n hw.ncpu)
cd /usr/obj/usr/src/amd64.amd64/tests/usr.sbin/bluetooth/blued
kyua test -k Kyuafile
cd /usr/src/usr.sbin/bluetooth/blued && make -j$(sysctl -n hw.ncpu)
cd /usr/src/lib/libble && make -j$(sysctl -n hw.ncpu)
cd /usr/src && git diff --check
```

Run `coverage.sh` and all applicable Mesh/kernel suites as well. Record exact
result totals and result database IDs. Hardware/root skips are residual risk,
not passes.

## Exit criteria

Do not declare the loop complete unless all are true:

- every current Kyua case has an explicit, unique, validated traceability row;
- every implemented normative requirement in scope has at least one
  production-exercising independent-oracle test;
- every normative literal/vector is test-owned, cited, and independent of the
  implementation definition;
- mutation checks demonstrate that representative wrong constants, bits,
  lengths, byte order, status codes, and state transitions are detected;
- no unexpected skips, failures, broken cases, build warnings, sanitizer
  findings, static-analysis findings, or traceability gaps remain;
- a final full review iteration finds no new gap.

Even then report “100% of the declared, enumerated requirement and
traceability matrix passed,” not “bug free,” “fully conformant,” or “Bluetooth
SIG qualified.” Formal qualification still requires the applicable SIG test
plan, PTS/RF/controller evidence, declarations, and listing process.

## Required output

Update the traceability/requirements/oracle artifacts and write a concise
report containing changed tests, exact citations, mutations caught, commands
and results, skips/blockers, requirements still outside scope, and the next
unreviewed slice. If any exit criterion is unmet, give the exact remaining
count and continue the loop instead of rounding it to 100%.
