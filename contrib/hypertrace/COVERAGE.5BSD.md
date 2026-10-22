# HyperTrace coverage baseline and plan

Measured 2026-10-20. This is an initial instrumented baseline, not a claim of
97% coverage or completed live qualification. Live tests remain deferred.

## Handoff and current measured refresh on 2026-10-21

The user requested finishing current tests and transferring further execution
to another agent. The Desktop handoff is
`/home/koryheard/Desktop/HyperTrace-Handoff-2026-10-21.md`.
No live testing was performed; the broad 97% objective remains unfinished.

All 11 suites in `coverage-library-refresh-final-20261021` passed. Fresh
profiles were merged with clean LLVM logs and source/binary hashes verified.
The complete library-object mapping measures **16,331/41,958 lines (38.92%),
7,720/21,851 branches (35.33%), and 671/1,362 functions (49.27%)**.
For comparison with the earlier explicitly narrower libdtrace path summary,
paths containing `/libdtrace/` measure **16,293/38,455 lines (42.37%),
7,709/20,457 branches (37.68%), and 667/1,194 functions (55.86%)**.
The latter excludes other mapped production sources, including disassembly
and glob helpers; it is not the full object denominator. Both are retained in
summary.json. Denominators did not change between the prior and new exports.
The failed first refresh used incorrect arguments for two test drivers; the
runner was fixed and its profiles were not merged into the successful run.

The second measured helper round (`coverage-helpers-round2-20261021`) passes:
`dt_string.c` 100% lines/98.15% branches; migration credential helpers
100%/100%; daemon config helpers 100%/96.43%; list helpers 100%/83.33%.
These are standalone configurations, not enclosing-component coverage.
The descriptor-only migration suite retains the full mapped source denominator
and covers just 3.78% lines/3.15% branches. Its broader state-machine suite
has not been rerun in this round. The current helper collector and library
refresh runner are maintained under `contrib/hypertrace/tests/`.

## Execution progress: list model, daemon configuration and transport faults

`tests/discovery-helpers.py` builds three independent test executables against
production implementations, using ASan/UBSan and parallel compilation. All pass:

- **Library lists:** 10,000 deterministic model operations on `dt_list.c` cover
  append, prepend, interior insertion, null-anchor insertion, removal and reuse.
  An independent array model checks both traversal directions, head/tail links,
  and membership of every candidate after each operation; final draining checks
  the empty state. Invalid list API usage and concurrent access are not tested.
- **Daemon configuration:** 9,930 properties cover path buffer capacities
  1, 2, 10, 11, 12, 32 and 256, trailing slash normalization, suffix fitting and
  unchanged output on rejection. Worker counts span 0–2048 with leading zeros,
  malformed input and integer overflow. These tests call the real inline
  helpers and do not initialize a daemon.
- **Migration descriptor transport:** eight syscall-injection modes exercise
  partial transfers, interrupted read/write, zero-byte progress, explicit and
  missing errno, poll timeout and poll interruption. Wrappers intercept only a
  reserved synthetic descriptor and assert expected calls. Separate real
  socketpair checks cover sending, receive timeout and peer EOF. Zero-length
  operations must make no I/O calls. This checks the existing behavior that
  poll EINTR propagates to the caller; it does not establish end-to-end deadline
  bounds, TLS behavior or performance under sustained backpressure.

Evidence, exact commands and source/binary hashes are in
`/usr/obj/5BSD-hypertrace-validation/discovery-helpers-20261020/`.
No production changes were needed. No installed daemon, VM or tracing device
was used. These are test results, not newly measured whole-component coverage.
The three-area discovery goal is complete; the broader 97% objective remains
unfinished and live qualification remains deferred.

## Execution progress: three additional helper areas and escape overflow fix

The new discovery round covered three areas outside the recent wire records:

1. **Compiler string conversions:** `tests/string-helpers.py` compiles the real
   `dt_string.c` with ASan/UBSan. Before the fix, a long hexadecimal escape
   triggered signed overflow at `x * 16`. The accumulator is now unsigned,
   retaining the low-byte conversion with defined modular arithmetic.
   **1,024 properties plus basename boundaries pass**, including byte escape
   round trips, hexadecimal runs up to 128 digits, all three-digit octal
   sequences, and repeated-underscore probe-name conversion.
2. **Compiler string table:** `tests/strtab-properties.py` uses the rebuilt
   libdtrace. **16 configurations pass**, combining eight buffer sizes (1–4096)
   with default hashing and forced collisions. Tests verify independent byte
   serialization, duplicate offsets, missing lookups, strings spanning buffers,
   and zero/error writer callbacks at multiple positions. Hash settings are
   restored inside the isolated process. Allocation-failure rollback remains
   outside this suite; the ctypes campaign is not sanitizer-instrumented.
3. **Migration credentials:** `tests/credential-properties.py` passes
   **15,440 ASan/UBSan checks** for lowercase/uppercase fingerprint decoding,
   invalid nonzero bytes at every position, and all partial-configuration
   combinations. It checks preservation of credential output on rejection and
   enabled-TLS signaling for partial configurations. It does not test a live
   TLS handshake or prove that supplied descriptors contain valid credentials.

The maintained libdtrace target was rebuilt using all logical CPUs, then all
**102 existing compiler positive/negative cases passed**, with accepted DOF
validated. No installed library was replaced. Evidence is under:

- `/usr/obj/5BSD-hypertrace-validation/string-helpers-before-20261020/`
- `/usr/obj/5BSD-hypertrace-validation/string-helpers-fixed-20261020/`
- `/usr/obj/5BSD-hypertrace-validation/string-library-fixed-20261020/`
- `/usr/obj/5BSD-hypertrace-validation/credential-properties-20261020/`

Previous whole-libdtrace percentages describe the earlier source/binary. The
new profiles are retained separately; no incompatible profile merge or new
97% claim is made. This completes the three-area discovery round, not the
broader coverage objective. Live testing remains deferred.

## Execution progress: rebind integrity and recovery file ownership

Two standalone ASan/UBSan suites exercise production header implementations:

- `tests/rebind-properties.py`: **9,398 checks** across local and foreign HRC2
  decisions. Independently laid-out expected bytes check encoding. Every
  single-bit wire mutation, every token-bit mismatch, and every single-bit
  embedded intent mutation is rejected. Recomputed checksums expose header,
  reserved-byte and plan/stage consistency validation separately from integrity
  checks. Rejected encoding/decoding must preserve prior caller output.
- `tests/recovery-permissions.py`: **2,185 checks** covering all 512 ordinary
  permission modes on regular files and directories, incorrect object types,
  hard-linked and unlinked records, invalid descriptors, rejection of a
  hard-linked controller lock, 128 contention attempts, close-on-exec, and
  reacquisition after release. Fixtures stay in the test object directory and
  are removed on success. File ownership by a different UID, power failure,
  and general descriptor leak freedom are not established by these checks.

Both passed without sanitizer findings. Evidence, build commands and hashes:
`/usr/obj/5BSD-hypertrace-validation/rebind-properties-20261020/` and
`/usr/obj/5BSD-hypertrace-validation/recovery-permissions-20261020/`.
These check serialization and local ownership rules, not authentication of a
live peer or permission to execute a rebind. No production code changed and
no new whole-component coverage percentage is claimed. Live testing remains
pending.

## Execution progress: independent transfer and journal properties

`tests/transfer-properties.py` passes **1,430 cases** against the production
transfer validation, inspection, import-decision, and replay-budget helpers.
Python constructs HTX1/HJM1/HJX1 bytes independently using explicit wire layouts
and SHA-256; a thin compiled adapter calls the real header implementations.
128 seeded journal combinations cover revoked and nonrevoked deliveries,
HTD4/HTD5 record sizes, bare and enveloped ELF payloads, varying chunk sizes,
kill records, and active/completed cleanups. Expected queue counts come from
the generated inputs rather than from production parsing results.

Negative cases include every truncated prefix of a representative journal
bundle, corruption in multiple regions, inconsistent frame lengths/counts,
invalid nested header fields, zero identities, duplicate records, trailing
bytes and invalid API parameters. Structural cases recompute the relevant
hashes so a digest mismatch cannot hide missing semantic checks. These tests
check helper-level structural validation; they do not establish execution
authority, validate every embedded delivery field, or simulate a process crash.

Evidence and hashes are in
`/usr/obj/5BSD-hypertrace-validation/transfer-properties-final-20261020/`.
This ctypes campaign is not sanitizer-instrumented and has no new production
coverage percentage. No installed daemon, VM or tracing device was used.

## Execution progress: protocol fuzzing and event lifecycle modeling

`tests/protocol-fuzz.py` builds the production cleanup-request and guest ELF
envelope parsers with libFuzzer, ASan and UBSan. The first bounded campaign
passed 200,000 inputs (seed 5987622), reaching 176 fuzzer coverage points and
351 features. These are fuzzer feedback counts, **not production line/branch
coverage percentages**. Independent wire-format oracles check acceptance,
parsed values, and preservation of caller output on rejection. The harness
also exercises reuse of the output vector after success and failure.
Artifacts, source/binary hashes, commands and the evolved corpus are under
`/usr/obj/5BSD-hypertrace-validation/protocol-fuzz-20261020/`.

`tests/event-model.cc` adds a deterministic reference model for registration,
lookup, retirement and removal in the production event registry. It checks
65,536 operations across 128 client lifetimes, outstanding-reference release
on registry destruction, and closure of the owned socket while the peer stays
open. It is registered in the sanitized native daemon component runner.
All 46 sanitized daemon component suites passed, including the new model.
Logs and results are under
`/usr/obj/5BSD-hypertrace-validation/native-daemon-model-20261020/`.
This is a sequential lifecycle model, not evidence of race freedom. Neither suite starts an installed daemon or accesses a tracing
device. The existing whole-component coverage percentages remain unchanged
until separately measured with compatible coverage instrumentation.

Next gaps identified in this review: process interruption at durable child and
handoff ledger update boundaries; admission/shutdown interleavings beyond the
existing concurrency cases; and trace-buffer ingestion (still untested).
These are follow-up targets, not completed tests. The event model validates
reference ownership and descriptor closure, not general heap leak freedom.

## Execution progress: request failures and transient I/O recovery

The real control CLI suite passes **57 cases**. Six added permanent faults stop
transmission at the client hello, frame-size word, request header, name-size word
or name payload, or fail acknowledgment reception. The independent peer checks
the exact prefix and byte count received before failure. Injection markers,
phase-specific diagnostics, socket closure and request-phase SHUT_RDWR shutdown
are required; handshake failure must close without request shutdown.

Four recovery cases inject send/receive EINTR and cap send/receive transfers to
one byte. Each must complete the exact request and statistics response. A short
transfer is credited only after the actual syscall returns one byte. An initial
receive attempt can return EAGAIN; the injector now remains armed until the
short transfer succeeds. A stricter audit exposed that false-positive test
assumption during development; the exploratory run is excluded. No production
changes were required.

Primary `dtracedctl.c` coverage is **235/258 lines (91.0853%), 117/132 branch
outcomes (88.6364%), and 7/7 functions (100%)**. The separately mapped I/O helper
header reaches 83/261 lines and 47/82 branch outcomes. All 57 final child profiles
were captured, production source/binary hashes match, denominators are unchanged,
and merge/export diagnostics are empty. Evidence:
`/usr/obj/5BSD-hypertrace-validation/coverage-control-cli-recovery-final-20261020/`.
Remaining paths are not excluded to raise percentages. The full component goal
is still incomplete; live services and tracing remain deferred.

## Execution progress: audited control-tool fault injection

The actual control-tool process suite now passes **47 cases**, adding nine
audited faults: socket creation failure, clock syscall failure, negative seconds,
negative nanoseconds, excessive nanoseconds, millisecond conversion overflow,
deadline addition overflow, and failures duplicating the first or second VM name.
Each fault must emit exactly one injection marker and produce the intended exit
status and error diagnostic. Clock cases verify closure of the created socket;
the second-name failure verifies that the first allocated name is freed once.
The audit does not claim complete heap-leak detection or array-allocation fault
coverage. No installed daemon or tracing device is used.

Production code and binary are unchanged. Only the separate interposer handles
fault selection and resource audit; its lines receive no production coverage.
The primary `dtracedctl.c` source now has **232/258 lines (89.9225%), 112/132
branch outcomes (84.8485%), and 7/7 functions (100%)**. The separately reported
`dtraced_io.h` mapping has **81/261 lines and 44/82 branch outcomes**. The
remaining control-tool and helper paths stay in their measured denominators.

All 47 child profiles were captured, source/binary provenance matches the prior
baseline, and merge/export diagnostics are empty. Passing results, fault and
cleanup markers, shim source, profiles and coverage export are retained under
`/usr/obj/5BSD-hypertrace-validation/coverage-control-cli-faults-audited-20261020/`.
The complete suite was rerun with the final resource-audit interposer; earlier
intermediate profiles were not needed. Further allocation and request-phase
I/O faults remain outstanding. The full 97% goal remains active and live
qualification stays deferred.

## Execution progress: real control-tool process and protocol testing

The maintained `usr.sbin/dtracedctl` target was built with source-based coverage
using all logical CPUs, without installation. `control-cli-offline.py` runs that
actual executable against independent Python Unix-socket peers. A narrow
connect interposer accepts only the production daemon address and redirects it
to the test-owned `/tmp/htctl-...` socket; other connect requests fail. The
installed daemon is never contacted. Production protocol and CLI code remain
unchanged and are not replaced by a component harness.

All **38 process cases pass**. They cover help and option conflicts, positional
and inline VM lists, empty/malformed/oversized lists, 4,095-byte names and 4,096
names, absent socket, cleanup and statistics success, fragmented server hello
and statistics, wrong protocol/kind, nonzero reserved hello fields, short hello,
negative acknowledgment, acknowledgment EOF, and truncated statistics. The peer
checks exact request-header bytes, name lengths/content, frame boundaries,
client hello fields and canonical padding. Statistics output is checked exactly,
including 64-bit values and UINT64_MAX.

The complete mapped primary `dtracedctl.c` source measures **228/258 lines
(88.3721%), 108/132 branch outcomes (81.8182%), and 7/7 functions (100%)**.
This is a new actual-executable baseline, not a merge with historical component
harness profiles. Mapped helper headers remain separate: `dtraced_io.h` has
73/261 lines and 37/82 branch outcomes; `dtraced_wire.h` has 93/743 lines and
19/20 mapped branch outcomes. Their differing mapped denominators are not
silently removed or averaged into a claimed whole-daemon percentage.

All 38 child profiles were captured; source/binary hashes match and merge/export
logs are empty. Evidence:
`/usr/obj/5BSD-hypertrace-validation/coverage-control-cli-20261020/`.
Build log: `/usr/obj/5BSD-hypertrace-validation/dtracedctl-coverage-build-20261020.log`.
Allocator, clock and syscall fault paths still need coverage, as do remaining
shared-header paths. Real-daemon authorization and live end-to-end behavior
remain unproven. The full 97% goal stays active with live tests deferred.

## Execution progress: program inspection and aggregation metadata fix

`program-inspection-offline.py` checks metadata and statement iteration using
the actual NODEV/NOSYS library. A C helper compiled against source-tree headers
verifies every ctypes program-info offset and structure size before testing.
The initial harness incorrectly used integer-sized attribute fields; the ABI
check established their byte-sized representation, and exploratory profiles
were excluded. Callback assertions check handle/program/data identity, unique
statement visits, positive and negative early-return status, prefix visitation,
and repeat iteration after termination. NULL metadata output is also exercised.

The corrected harness found a production bug: `dtrace_program_info()` subtracted
aggregation parameters (`dtad_arg`) from the ordinary-record count. A count-only
aggregation reported one ordinary record, keyed aggregation reported three, and
linear/logarithmic histogram parameters wrapped the count to 4,294,967,287 and
4,294,770,687 respectively. Evidence is preserved under
`/usr/obj/5BSD-hypertrace-validation/coverage-program-inspection-before-20261020/`.

The metadata walk now uses a forward-only lookahead to identify the next
aggregation and exclude its preceding `dtad_ntuple` actions. Each action is
visited at most twice; no allocation is needed. Excluding tuple actions directly
also handles void-valued weight increments, which cannot safely be handled by
blindly subtracting the tuple length from previously counted records. Ordinary
trace records before and after aggregations remain counted.

All **48 cases pass**, including 16 explicit boundary/metadata cases and 32
seeded mixed-action models across clauses, with **262 early-termination checks**
plus complete and repeated traversal. Generated programs explicitly declare
variables and isolate speculation in valid clauses; initial invalid generator
outputs were excluded. No compiled action, including destructive actions, is
executed. Evidence and ABI results:
`/usr/obj/5BSD-hypertrace-validation/coverage-program-inspection-verified-20261020/`.

The library was rebuilt with all logical CPUs, and all nine previously measured
offline suites were rerun successfully (ELF/library/compiler corpus, compiler
API, linker, CLI, CTF boundaries, formatter/property cases, guarded histogram
cases, differential compiler and disassembly). Fresh **766-profile** coverage is
**16,288/38,455 lines (42.3560%), 7,702/20,457 branch outcomes (37.6497%), and
667/1,194 functions (55.8626%)**. The production change alters the mapping;
no historical profiles were merged. Source/binary hashes match and merge/export
logs are empty. Current authoritative evidence:
`/usr/obj/5BSD-hypertrace-validation/coverage-infofix-combined-20261020/`;
individual reruns: `coverage-infofix-reruns-20261020/` under the same root.
Build log: `program-info-rebuild-20261020.log`. Full 97% coverage remains unmet;
live qualification stays deferred.

## Execution progress: compiler disassembly coverage

`disassembly-offline.py` runs the actual CLI with `-e -S -x nolibs` and the
NODEV/NOSYS shim across all 51 accepted compiler corpus programs. All cases
pass. Forty-nine emit listings; independent decoding checks **499 instructions,
41 mnemonics and 370 operand representations**. Opcode names come from the DIF
interface header rather than the disassembler's table. Sequential instruction
offsets, encoded opcodes and selected register, branch and constant operands
must agree with the printed listing. Deliberate offset, opcode, register and
mnemonic corruptions were all rejected; those oracle checks receive no
production coverage credit.

Two cases (`aggregate-clear` and `format-escaped-percent`) produce synthetic
constant/return DIF directly in `dt_cc.c`, bypassing `dt_as()` and its -S hook.
Their validated reference DOF is checked for the exact expected instruction
sequences; no CLI listing is expected. They remain in the suite rather than
being counted as disassembler execution. -S does not therefore establish
complete visibility of all synthetic DIF. Initial exploratory assumptions about
these cases failed and their profiles were excluded from the final merge.

Previously uncovered `dt_dis.c` now measures **312/440 lines (70.9091%),
88/140 branch outcomes (62.8571%), and 19/23 functions (82.6087%)**. Whole
mapped libdtrace reaches **16,228/38,444 lines (42.2120%), 7,668/20,445 branch
outcomes (37.5055%), and 665/1,194 functions (55.6951%)**. Source/binary and
reference-artifact hashes were verified; mapping denominators are unchanged and
merge/export diagnostics are empty. Results, listings, reference hashes and
coverage evidence are retained under
`/usr/obj/5BSD-hypertrace-validation/coverage-disassembly-verified-20261020/`.
This tests rendering/decoding consistency, not execution semantics of DIF.
Program-inspection APIs and remaining disassembler paths still need work.
Live qualification remains deferred and the full 97% goal remains active.

## Execution progress: differential compiler API testing

`compiler-differential.py` compares 102 existing language cases through string
and FILE compilation, both unchanged and with a comment/blank-line prefix.
All **408 compilations pass**: the 51 valid programs yield matching canonical
DOF through all four paths, and the 51 invalid programs preserve their diagnostic
tags and required diagnostic text. Each emitted DOF also passes the independent
structural validator. Compilation remains NODEV/NOSYS with system libraries and
preprocessing disabled; FILE input uses temporary streams.

Raw byte comparison initially failed because `dt_program.c` assigns statement
pointers to `dtad_uarg` and `dt_dof.c` serializes them as `dofa_uarg`. The oracle
now canonicalizes only those eight-byte action fields, retaining zero values
and pointer-sharing relationships. All remaining bytes are compared unchanged.
Raw and canonical artifacts and exact cookie offsets are saved. Separate checks
confirmed relocation equivalence, instruction-change detection, cookie-alias
change detection, and unchanged bytes outside cookie fields. An initial trailing
newline transformation was corrected because it legitimately changes the error
for an unterminated string; the final prefix transformation preserves EOF.

This is differential testing of entry points in the same compiler, not agreement
with an independent compiler or proof of runtime DIF semantics. It does not
exercise preprocessing. Exploratory failed profiles are excluded. Passing
results and provenance are retained under
`/usr/obj/5BSD-hypertrace-validation/coverage-compiler-differential-final-20261020/`.

The compatible cumulative export measures **15,902/38,444 lines (41.3641%),
7,513/20,445 branch outcomes (36.7474%), and 645/1,194 functions (54.0201%)**.
Source/binary hashes match, denominators are unchanged, and merge/export logs
are empty. This class adds one covered branch outcome while checking output
consistency across substantially more inputs. The full coverage goal remains
active and live testing remains deferred.

## Execution progress: property-based and metamorphic testing

A new testing class now supplements individual regression examples. The seeded
`histogram_properties.py` model generates 96 configurations across quantize,
lquantize and llquantize, including empty, endpoint-only, sparse and dense signed
counts. Each configuration is rendered unchanged, multiplied by three and
negated: **288 generated variants**, bringing the formatter suite to **469
passing cases**. Bucket labels are checked against a separate model using exact
rational arithmetic for logarithmic intervals. Ninety-six metamorphic groups
check that transformations preserve labels, transform counts correctly and
conserve total counts, including trimmed zero buckets.

Five deliberate output/oracle corruptions (scaled count, negated count, renamed
label, dropped zero label and wrong total) were rejected by the relation checker.
These checks do not count as production coverage. The fixed seed, parameters,
per-case output, driver/model hashes and relation results are retained under
`/usr/obj/5BSD-hypertrace-validation/coverage-histogram-properties-20261020/`.
This is bounded seeded property testing, not coverage-guided fuzzing or an
exhaustive proof; it currently targets histogram rendering only.

Provenance-checked cumulative library coverage is **15,902/38,444 lines
(41.3641%), 7,512/20,445 branch outcomes (36.7425%), and 645/1,194 functions
(54.0201%)**. The new class adds one covered branch outcome and substantially
more input/relationship checks; passing-case counts are not used as a coverage
percentage. Mapping denominators are unchanged and export diagnostics are empty.
Live qualification remains deferred and the full component goal remains active.

## Execution progress: malformed logarithmic records fixed

Guard-page tests against the actual library reproduced two SIGSEGVs (header-only
and one zero count), assertions for extra counts and overflowing magnitudes,
and a timeout for overflowing low magnitude. Truncated, partial and invalid-step
records also returned success. The isolated children disable core dumps and
never open a tracing device. Pre-fix evidence is preserved in
`/usr/obj/5BSD-hypertrace-validation/llquantize-bounds-before-20261020/`.

`dt_format_llquantize_prepare()` now validates step divisibility, representable
signed bucket boundaries, and the exact count-array length before accessing
counts. Text and structured renderers stop at the last required boundary instead
of multiplying it into an unused, potentially overflowing next power. Eighteen
guarded cases (nine malformed inputs through both rendering entry points) now
return the specific record-mismatch error without signals or timeouts. This
closes the count-array safety follow-up recorded below. It is not a claim that
all other malformed aggregation types have been audited.

The valid formatter suite passes 181 cases, including a high-power boundary and
steps that divide a higher power of the factor. All previously measured offline
ELF/library, compiler API, linker, CLI and CTF suites were rerun successfully.
The ELF/library runner includes the 102 compiler cases, options, pragmas and
allocation-fault cases. No live tests were run. Build log:
`/usr/obj/5BSD-hypertrace-validation/llquantize-bounds-rebuild-20261020.log`.

The new production checks change the coverage mapping, so historical profiles
were not merged. A fresh 503-profile export measures **15,902/38,444 lines
(41.3641%), 7,511/20,445 branch outcomes (36.7376%), and 645/1,194 functions
(54.0201%)**. Source/binary provenance was checked and merge/export diagnostics
are empty. Authoritative cumulative evidence:
`/usr/obj/5BSD-hypertrace-validation/coverage-logfix-combined-20261020/`.
Suite evidence is in `coverage-logfix-reruns-20261020/`,
`coverage-printf-log-fixed-20261020/` and `llquantize-bounds-both-20261020/`
under the same validation root. The full 97% goal remains incomplete.

## Execution progress: logarithmic histogram rendering

The actual-library formatter suite now passes **179 cases**. Fourteen additions
cover empty, underflow, overflow, middle, negative and mixed-count logarithmic
histograms, decimal bucket steps across orders, short headers, invalid factors,
equal/reversed orders, zero steps and insufficient steps. Expected bucket maps
are explicit; the decimal map uses independently enumerated decimal labels.

The compatible cumulative export measures **15,870/38,422 lines (41.3045%),
7,491/20,423 branch outcomes (36.6792%), and 644/1,194 functions (53.9363%)**.
All prior mapped source and binary hashes matched, denominators are unchanged,
and merge/export diagnostics are empty. Evidence is retained under
`/usr/obj/5BSD-hypertrace-validation/coverage-printf-logarithmic-20261020/`.
`dt_consume.c` now has 469/2,860 covered lines and 191/1,522 branch outcomes.
These are rendering tests, not evidence of live trace ingestion.

Open safety follow-up: `dt_format_llquantize_prepare()` derives the bucket count
from payload length but does not establish that the count array matches its
parameters. In particular, an empty array selects display bins zero and one.
A guarded-memory regression and validation of malformed count lengths and
arithmetic parameters are still needed; passing valid histograms do not prove
those paths safe. The full 97% goal remains active and live tests deferred.

## Execution progress: linear histogram rendering

All 165 formatter cases pass, including eight new linear-quantization cases:
empty, underflow, overflow, middle bucket, negative count, mixed signed counts,
short header and truncated count array. Explicit expected bucket labels and
counts are checked against actual library output; malformed records must fail.
No tracing device or live consumer was used.

After verifying all baseline source and binary hashes, the passing profiles were
merged with the compatible post-fix cumulative baseline. Whole mapped libdtrace
now measures **15,751/38,422 lines (40.9947%), 7,436/20,423 branch outcomes
(36.4099%), and 641/1,194 functions (53.6851%)**. Denominators are unchanged;
merge and export diagnostics are empty. This remains below the 97% target.
`dt_consume.c` reaches 356/2,860 lines and 137/1,522 branch outcomes; this does
not establish trace-buffer ingestion or callback coverage.

Results, raw profiles, provenance and cumulative export are retained under
`/usr/obj/5BSD-hypertrace-validation/coverage-printf-linear-20261020/`.
The full component plan, including compiler and auxiliary tools, remains active.
Live qualification remains deferred.

## Execution progress: post-fix cumulative library baseline restored

The remaining previously measured offline suites were rerun against the rebuilt
histogram-fixed library: 28 CLI cases, 11 linker cases, 21 malformed ELF
boundaries repeated three times, seven ELF round trips with checksummed variants
and 79 malformed graph/table cases, six program identity checks, 289 option
checks, 53 pragma cases, eight allocation-fault fixture groups, and the CTF
relocation/index boundary fixture. The expanded compiler corpus also passes
within the library runner. No suite failed and no LLVM profile errors were found
in the logs. The CTF fixture uses sanitizers; this does not imply the entire
shared library was rebuilt with sanitizers.

The fresh cumulative export now records **15,663/38,422 lines (40.7657%),
7,404/20,423 branch outcomes (36.2532%), and 638/1,194 functions (53.4338%)**.
This supersedes the narrow post-fix baseline and the historical pre-fix aggregate
for current mapped libdtrace coverage. The 97% target remains unmet. All prior
post-fix mapped-source/binary hashes were verified; the merge used only fresh
passing profiles and produced no merge/export diagnostics.

Combined evidence:
`/usr/obj/5BSD-hypertrace-validation/coverage-postfix-combined-20261020/`.
Individual results/logs/profiles are retained in `coverage-postfix-elf-library-20261020/`,
`coverage-postfix-linker-offline-20261020/`, `coverage-postfix-cli-offline-20261020/`,
and `coverage-postfix-ctf-bounds-20261020/` under the same validation root.
The combined profile also includes the fresh post-fix formatter/compiler/API
baseline; no pre-fix aggregate was reused. Tests remain offline and live
qualification stays deferred.

## Execution progress: highest quantize bucket bug fixed

Seven added histogram cases test empty, positive, negative, mixed-sign, lowest
and highest occupied buckets, plus malformed record size. Parsed bucket labels
and counts are compared with explicit expected maps. The highest-only case
reproduced a production defect: a count of seven in the 2^62 bucket printed an
empty -1/0/1 histogram. `dt_format_quantize_prepare()` treated reaching the last
bucket as proof that the entire histogram was empty, without checking that
bucket's value. It now selects the empty display only when that value is zero.

The instrumented library was rebuilt with all logical CPUs. **157 formatter
cases, 102 compiler cases and 21 compiler API cases pass** against the rebuilt
binary (280 total). The failing pre-fix case is retained under
`coverage-printf-histogram-before-20261020/`; final formatter results and fresh
coverage export are under `coverage-printf-histogram-fixed-20261020/` in the
validation root. Compiler reruns are in `coverage-histogram-compiler-20261020/`
and `coverage-histogram-api-20261020/`. No live tests were performed.

The production branch change invalidates historical cumulative profiles. The
new export deliberately includes only those three fresh suites, giving
**9,522/38,422 lines (24.7827%), 4,387/20,423 branches (21.4807%), and 394/1,194
functions (32.9983%)** for whole mapped libdtrace. This lower percentage reflects
a narrower newly rerun suite set, not a measured coverage regression. Earlier
40.4492%/35.9483% cumulative figures are historical pre-fix evidence and must not
be reported as coverage of the current binary. Rerunning the remaining linker,
ELF, option, pragma, fault and CLI suites is outstanding before restoring the
full cumulative baseline.

Within the fresh export, `dt_consume.c` reaches **274/2,860 lines (9.5804%)** and
**106/1,522 branch outcomes (6.9645%)** from arithmetic and histogram rendering.
Trace-buffer ingestion remains untested. Source/binary hashes, passing profile
list, raw results and warning-free export are retained with the final evidence.

## Execution progress: aggregation arithmetic rendering

The synthetic-record formatter corpus expands to **150 passing cases**, adding
average/empty-average, empty-standard-deviation, malformed aggregation sizes,
and **128 seeded standard-deviation datasets**. Inputs include signed 45-bit
samples and 128-bit sums of squares. Python arbitrary-precision arithmetic and
integer square root provide the reference output, preserving the production
algorithm's truncation convention. Exact rendered results are compared through
the actual `dtrace_fprintf` aggregation callbacks, not a copied implementation.

The tests now exercise arithmetic helpers in `dt_consume.c`: **167/2,859 lines
(5.8412%), 46/1,520 branch outcomes (3.0263%), and 11/82 functions (13.4146%)**.
This is aggregation arithmetic/output coverage only. Trace-buffer ingestion,
lifecycle callbacks and live consumption remain unproven; the nonzero source
percentage must not imply those paths ran.

After compatibility checks and a clean export, mapped whole-libdtrace coverage
is **15,541/38,421 lines (40.4492%), 7,341/20,421 branches (35.9483%), and
630/1,194 functions (52.7638%)**. This adds 188 lines, 56 branch outcomes and
13 functions with unchanged denominators. No production changes were required.

Evidence:
`/usr/obj/5BSD-hypertrace-validation/coverage-printf-aggregation-20261020/`.
The full 97% goal remains open. These tests use synthetic payloads, NODEV/NOSYS
handles and temporary output streams; live testing stays deferred.

## Execution progress: offline record rendering

`printf-records-offline.py OUTPUT LIBRARY` feeds synthetic record descriptors
and payloads to the actual `dtrace_fprintf` implementation using NODEV/NOSYS
handles and temporary output streams. **17 cases pass**, checking exact rendered
text for signed/unsigned/wide integers, hex/octal, characters, strings, precision,
dynamic positive/negative width, dynamic precision, mixed fields and literals.
Missing records, truncated buffers, out-of-range offsets and misalignment return
errors with diagnostics. The fixture closes format objects, streams and handles.

The first run incorrectly used zero record alignment for dynamic width/precision
inputs. The final fixture supplies valid alignment metadata; exploratory profiles
are excluded. This was a fixture repair, not a production behavior change.

After source/binary compatibility verification, passing profile aggregation gives
**15,353/38,421 lines (39.9599%), 7,285/20,421 branches (35.6741%), and 617/1,194
functions (51.6750%)** for mapped libdtrace: gains of 189 lines, 90 branch outcomes
and ten functions with unchanged denominators. `dt_printf.c` reaches 559/1,283
lines (43.5698%). **`dt_consume.c` remains 0/2,859 lines**; synthetic formatting
must not be described as live-buffer consumption coverage. That substantial
runtime gap remains an explicit next testing requirement.

Final evidence and warning-free export:
`/usr/obj/5BSD-hypertrace-validation/coverage-printf-records-final-20261020/`.
No tracing devices, installed daemons or live buffers were operated. Overall
coverage remains below the target, and live qualification stays deferred.

## Execution progress: public compiler API modes

`compiler-api-offline.py OUTPUT LIBRARY` adds **21 passing API cases** using
fresh NODEV/NOSYS handles with system D libraries disabled. Eleven type cases
check primitive, pointer, array and qualified type sizes through the returned
CTF container, plus malformed and null type inputs. Ten program cases cover
empty-program policy, null source, unknown flags, numeric macro substitution,
missing/defaulted macro arguments, unused-argument policy, and tagged errors.
Negative program cases assert the intended diagnostic; accepted programs pass
the structural DOF checker and retain artifacts. Internal expression-only
compilation remains outside this public-API fixture's coverage.

After verifying prior binary/mapped-source hashes, merging final passing API
profiles raises whole mapped libdtrace to **15,164/38,421 lines (39.4680%),
7,195/20,421 branch outcomes (35.2333%), and 607/1,194 functions (50.8375%)**.
The increments are 111 lines, 57 branch outcomes and two functions, with unchanged
denominators and clean export diagnostics. CTF helper execution is not folded
into these libdtrace-only percentages. The library target remains unmet.

Final results, provenance, DOF artifacts, profile list and export:
`/usr/obj/5BSD-hypertrace-validation/coverage-compiler-api-final-20261020/`.
Only the final diagnostic-asserting run was merged; the initial API run is
retained separately. No file preprocessing, subprocess execution by D programs,
tracing-device operation, or live kernel testing was performed.

## Execution progress: translator compiler paths

Twelve added translator cases bring the offline corpus to **102 passing cases**
(51 accepted, 51 rejected). Positive cases exercise scalar/pointer inputs, union
outputs, multiple translated members, typedef input and declaration-only
translators. Negative cases require specific diagnostics for scalar or incomplete
outputs, unknown members, incompatible member types, redeclaration, and missing
translations. All accepted programs pass the structural DOF oracle and retain
their generated artifacts; compilation does not execute D program actions.

Compatible passing profiles were merged only after prior binary/source hash
verification. Whole mapped libdtrace coverage reaches **15,053/38,421 lines
(39.1791%), 7,138/20,421 branch outcomes (34.9542%), and 605/1,194 functions
(50.6700%)**. This adds 97 executed lines, 42 branch outcomes and one function
with unchanged denominators and empty coverage-export diagnostics. It remains
well below the complete-library target.

Final evidence, retained DOF, oracle hash, results and coverage export:
`/usr/obj/5BSD-hypertrace-validation/coverage-compiler-translators-final-20261020/`.
The initial translator run is separate in `coverage-compiler-translators-20261020/`;
only the final diagnostic-asserting run was included in the new aggregate.
Live testing remains deferred; no production source change was needed.

## Execution progress: independent compiler DOF structure checks

The compiler harness now validates emitted DOF beyond magic bytes and total
size. The independent Python checker verifies model/encoding, header and section
table bounds, loadable-section ranges, alignment, entry-size divisibility,
ECB/probe/action/DIFO section links and expected target types, probe string
offsets/termination, and padding. Probe descriptor checks include the local VM
identifier extension. All **90 compiler cases pass**, and the **45 accepted
programs' DOF artifacts** are retained with hashes and structural summaries.

A separate mutation test corrupts a real generated artifact in **13 ways**:
magic, encoding, header/section/file sizes, table and section ranges, padding,
alignment, ECB link range/type, probe string offset, and string termination.
Every mutation is rejected. The checker, mutation driver, harness, format header,
and all artifacts are hashed in a separate provenance record.

Evidence:
`/usr/obj/5BSD-hypertrace-validation/coverage-compiler-dof-20261020/`.
These checks strengthen the test oracle; they do not add production execution
coverage merely by adding harness code. The previous whole-library coverage
baseline remains authoritative until a compatible export is recomputed. This
checker covers the emitted corpus's structure, not every DOF section kind,
relocation rule, instruction semantic, or live kernel-loader behavior. Those
remain explicit gaps; no tracing device or kernel operation was performed.

## Execution progress: aggregation and format compiler coverage

The offline compiler corpus now has **90 passing cases** (45 accepted and 45
rejected), adding 35 aggregation/format cases. These cover clear, normalize,
denormalize, truncation, formatted/default/multiple aggregation output, weighted
and log-linear quantization, format width/precision, integer modifiers, pointers,
and escaped percent signs. Negative cases cover argument counts/types, missing
aggregations, incompatible aggregation keys, quantization parameter boundaries,
and malformed formats. All 23 new negative cases require a specific diagnostic
substring, so an unrelated compilation failure cannot satisfy their oracle.

The first exploratory run exposed an incorrect positive expectation for `%hhd`:
the DTrace formatter rejects that modifier. The final corpus keeps this as an
explicit negative case and tests `%hd`, `%ld`, and `%lld` positively. Exploratory
profiles remain excluded. Accepted programs produce checked DOF; actions are
compiled only and never executed against live probes.

After verifying unchanged prior binary and mapped-source hashes, merging only
passing profiles produces **14,956/38,421 lines (38.9266%), 7,096/20,421 branch
outcomes (34.7485%), and 604/1,194 functions (50.5863%)** for mapped libdtrace.
That adds 429 lines, 176 branch outcomes, and nine functions with unchanged
denominators. Coverage exports have no diagnostics; the full-library 97%
target remains unmet.

Final evidence:
`/usr/obj/5BSD-hypertrace-validation/coverage-compiler-actions-final-20261020/`.
The separate `coverage-compiler-actions-20261020/` directory retains the failed
exploratory expectation. No production source changes or live operations were
needed for this increase.

## Execution progress: compiler type and semantic coverage

The actual-library NODEV/NOSYS compiler corpus expands from 33 to **55 cases**:
33 positive and 22 negative. New cases exercise structs/unions, array typedefs,
nested structures, member access, pointer arithmetic/indexing, inline constants,
enum expressions, conditional strings, compound bitwise assignment and standard
deviation aggregation. Rejection cases cover incomplete types, duplicate or
unknown members, invalid dereference, void arrays/values, incompatible inline
types, and string multiplication. Every accepted program produces DOF with
checked magic/size; every rejection supplies a diagnostic. D program actions
are compiled only, not executed against live probes.

An exploratory string-subtraction rejection expectation was incorrect: the
compiler accepts it. That exploratory run remains separate and contributes no
profiles. The final corpus uses string multiplication for the invalid arithmetic
case. All 55 final cases pass.

Before aggregation, all prior mapped-source and binary hashes were verified
against the existing provider/CLI baseline. Only the compatible passing profile
and the fresh passing compiler profiles were merged; coverage export diagnostics
are empty. Whole mapped libdtrace coverage is now **14,527/38,421 lines (37.8101%),
6,920/20,421 branch outcomes (33.8867%), and 595/1,194 functions (49.8325%)**.
This adds 417 executed lines, 205 branch outcomes and three functions without
changing the mapped denominator. The full library remains far below 97%.

Evidence, corpus results, provenance, profile list and full export:
`/usr/obj/5BSD-hypertrace-validation/coverage-compiler-types-20261020/`.
Exploratory evidence is retained in the separate
`coverage-compiler-types-exploratory-20261020/` directory. No tracing device,
installed daemon, live VM or kernel module was operated.

## Execution progress: libc source-alias provenance

The generated-input audit now records the evaluated JEMALLOCSRCS, GDTOASRCS,
and CANCELPOINTS_SRCS lists and the explicit C99_Exit.c rule. For unresolved
libc source names matching these rules, it retains original source path/hash,
recipe path/hash, and the declaration that selected the alias. Each recipe must
be present in the inventory's evaluated Makefiles; stale recipe hashes fail.

This attributes **486 additional occurrences** to source aliases, alongside
5,408 syscall-assembly occurrences, leaving **682 still unattributed**. The
6,576 unresolved output occurrences remain intact: an identified alias recipe
is not proof that its build-tree link was created or its source was executed.
All 486 original source and recipe hashes were checked. A deliberately stale
inventory fixture was rejected before make evaluation, validating the provenance
guard without modifying any production source.

Evidence and integrity checks:
`/usr/obj/5BSD-hypertrace-validation/coverage-generated-aliases-20261020/`.
This removes ambiguity about allocator/number-conversion source identity, but
adds no line, branch, or function coverage. Generated artifacts, assembly
validation, remaining input attribution, and execution coverage remain open.

## Execution progress: generated syscall assembly attribution

`coverage-generated-audit.py INVENTORY OUTPUT` evaluates the actual SASM,
SPSEUDO, and recipe dependency lists for libc/libsys across the inventory's
architecture/snapshot configurations. It rejects stale inventory Makefile
hashes, preserves commands and generator-input hashes, and only attributes
unresolved SRCS names that match the evaluated generation declarations.

Of the **6,576 unresolved input occurrences**, **5,408** are now attributed to
declared syscall assembly, leaving **1,168 still unattributed**. All 12 relevant
configuration declarations have existing, hashed recipe inputs. The unresolved
output count is still 6,576: attribution does not establish that generated
outputs exist, compile, execute, or are covered. Every audit entry explicitly
sets `output_verified` false and grants no execution coverage. Assembly requires
its own validation strategy; it cannot silently disappear from scope because
ordinary C/C++ LLVM source coverage does not measure it.

Evidence:
`/usr/obj/5BSD-hypertrace-validation/coverage-generated-audit-20261020/audit.json`.
The counts reconcile exactly with the source inventory. Remaining attribution
work is concentrated in libc (726 occurrences), libmd (102), DTrace kernel
inputs (54), libdtrace (36), and libelf (36), plus other generators. No build,
installation, or live tracing operation was performed.

## Execution progress: declared LIBADD manifest closure

`coverage-inventory.py --dependencies OUTPUT` now follows evaluated LIBADD
edges recursively, resolving source directories from the build system's
`LIB<name>DIR` and `_LIB_OBJTOP` values. This avoids guessing aliases such as
pthread/libthr, cplusplus/libc++, and fidl_bsd/libfidl. Each discovered source
Makefile is evaluated under the same architecture and snapshot configuration;
cycles are deduplicated. Install groups and additional build metadata are now
recorded separately rather than mixing FIDL variables into install groups.

The scan completes **329 evaluations with zero failures**, spanning **56 distinct
target directories** across the six configurations. A separate closure audit
verifies **579 dependency edges**: every resolved edge has a matching evaluated
manifest, with no duplicate configuration keys or unresolved source-directory
mappings. This closes the declared LIBADD manifest graph for these seeds and
settings, not implicit compiler/runtime or static-only `_DP` dependencies.

The broader inventory contains **5,342 distinct resolved inputs** and retains
**6,576 unresolved/generated occurrences** explicitly. No execution coverage is
credited merely from inclusion in this graph. Generated-output provenance,
additional option configurations, implicit dependency inventory, and staged
installation/package verification remain open.

Evidence and hashed closure audit:
`/usr/obj/5BSD-hypertrace-validation/coverage-inventory-libadd-20261020/`.
Only build-variable queries and source hashing were performed; no compilation,
installation, daemon execution, or live kernel tracing was involved.

## Execution progress: binding and tool dependency inventory expanded

The evaluated inventory now includes `libservice`, `libfidl` (`fidl_bsd`),
`libchannel`, and `liblogcmp`, which support the tracing tools. It records
`LIB_CXX`, generated-source/cleanup declarations, FIDL binding names, evaluated
schema/library/generated-source variables, binding generator scripts/templates,
and capability-image manifests. FIDL schemas resolve relative to SRCTOP as the
build specifies. The dtraced rc script and its installation Makefile are hashed
as supplemental startup/install evidence, without implying installation tests.

The refreshed inventory evaluates **138 configurations with zero failures**:
23 seed targets across amd64, aarch64 and riscv64, each with snapshots on/off.
It resolves **513 distinct input paths**, up from 450, and retains **288
unresolved/generated input occurrences** across the broader scope. The increased
unresolved count is explicit scope growth, not evidence that generated outputs
were built. All added binding/schema/capimage inputs checked for BSDTrace,
libtracecmp and liblogcmp resolve with hashes (23, 22 and 22 occurrences in the
amd64/no-snapshot configuration respectively).

Evidence:
`/usr/obj/5BSD-hypertrace-validation/coverage-inventory-bindings-20261020/inventory.json`.
Only make variable queries were executed; no builds, installation, or live tests.
This remains a seed inventory: transitive LIBADD closure, generated-output
attribution, conditional option closure, and staged/package verification remain
open. Source discovery does not establish execution coverage for these inputs.

## Execution progress: run-request portable target enforced

Two new ATF cases cover null/zero-limit rejection and **392 address-range
combinations** (14 cpuset addresses by 14 exit addresses under 32-bit and 64-bit
address ceilings). A 128-bit endpoint oracle checks validity and overlap without
reproducing the implementation's subtraction arithmetic. Cases include zero,
adjacency, reversed ordering, containment, and top-of-address-space overflow.
The input request must remain unchanged for both acceptance and rejection.

All **114 startup ATF cases** pass. The dedicated run-request source reaches
**41/41 executable lines, 47/48 branch outcomes (97.9167%), and 4/4 functions**.
The collector now enforces these minima and reports its 97% target as met,
alongside the event source. The remaining private range-helper zero-length
outcome remains in the denominator; public callers reject zero lengths earlier.
The earlier standalone validator measurement is not merged into these profiles.

Fresh final evidence:
`/usr/obj/5BSD-hypertrace-validation/coverage-startup-run-target-20261020/`.
Initial expanded-suite evidence:
`/usr/obj/5BSD-hypertrace-validation/coverage-startup-run-matrix-20261020/`.
These are amd64 userland executions of the portable production source with
simulated address ceilings, not execution of a 32-bit kernel or other CPU
architecture. Broader kernel integration, compiler/tools/library coverage and
live qualification remain outstanding under the unchanged full goal.

## Execution progress: management request state-space coverage

Three added ATF cases enumerate **4,860 distinct status configurations** against
an independent oracle for the three permitted wire-state families, check
malformed request/status fields, null arguments, operation limits, maximum
vCPU enforcement, and status/output overlap. Successful encodings are compared
with the complete expected output; rejected encodings preserve the destination.
The matrix verifies that request and status inputs remain unchanged.

All **112 portable startup cases** pass. Dedicated request coverage improves to
**144/146 lines (98.6301%), 154/160 branch outcomes (96.25%), and 6/6 functions**.
The regression gate enforces the improved counts. Its branch target remains
unmet. Six defensive outcomes remain in the denominator. Existing tests in this
suite invoke private defensive helpers directly; these measurements therefore
include that unit-test coverage and must not be described as exclusively
public-API or kernel integration coverage. The new tests use public APIs only.

Final evidence:
`/usr/obj/5BSD-hypertrace-validation/coverage-startup-request-gated-20261020/`.
The intermediate `coverage-startup-request-matrix-20261020/` run repeated each
status combination three times; the final run removes those duplicate iterations
and covers each of the 4,860 combinations once. Other suite gates remain green.
No production behavior, source denominator, or live-testing constraint changed.

## Execution progress: event source exceeds the portable coverage target

Six additional ATF cases exercise all named nonempty receipt/claim/run-token
fields, null and overlapping arguments, valid-but-divergent token fields,
active-claim conflicts, absent-event consumption, invalid publication kinds,
invalid state, and publication generation exhaustion. Assertions verify error
codes and preservation of state and existing destination data.

All **109 portable startup cases** pass. The dedicated event source reaches
**362/363 executable lines (99.7245%), 350/354 branch outcomes (98.8701%), and
22/22 functions (100%)**. Its regression minima now enforce these counts and
its explicit `target_97_met` flag is true. The four remaining branch outcomes
are private overlap-helper null/zero-length guards; they remain in the
354-outcome denominator. No production code or denominator was changed.

Final fresh evidence and passing gates:
`/usr/obj/5BSD-hypertrace-validation/coverage-startup-event-target-20261020/`.
Intermediate boundary and transition runs remain separately available in
`coverage-startup-event-arguments-20261020/` and
`coverage-startup-event-transitions-20261020/` under the same validation root.

This meets the per-source portable event target only. Other startup suites,
compiler, libraries, daemons, tools, build/install scope, architectures, and
live kernel execution retain their outstanding coverage requirements. No
cross-binary overlapping source percentages are combined.

## Execution progress: event credential and state fault matrices

Three new ATF cases exercise 13 malformed receipts, 13 malformed claims, and
12 invalid configurations each for event state and run tokens. Checks cover
reserved fields, owner/generation/storage identity, invalid event kinds and
vectors, pending masks, and active-claim invariants. Rejected consume, finish,
and abort operations preserve state and credentials. Invalid-state operations
also preserve empty receipt, claim, and token destinations.

All **103 startup ATF cases** pass. The dedicated event source rises from
344/363 to **351/363 executable lines (96.6942%)**, and from 224/354 to
**274/354 branch outcomes (77.4011%)**, with **22/22 functions** covered.
The collector now enforces these increased minima; all seven suite regression
gates pass. No production edits or denominator exclusions were made. The 97%
line-and-branch target remains unmet for this source.

Final evidence:
`/usr/obj/5BSD-hypertrace-validation/coverage-startup-event-gated-20261020/`.
Initial fault-matrix evidence is retained separately in
`/usr/obj/5BSD-hypertrace-validation/coverage-startup-event-faults-20261020/`.
Remaining event work includes public argument/alias boundaries, nonempty output
fields, and further valid token state transitions. All results remain portable
source measurements; live kernel and architecture execution are deferred.

## Execution progress: committed handshake validation and regression gates

The committed-kernel corruption test now exercises zero expected vCPUs,
invalid bound records, consistent but incomplete admission, missing BSP after
complete admission, and overlapping handshake/record storage. All public
operations reject these states without modifying handshake, records, or output.
Handshake coverage is **343/350 lines (98%), 242/258 branch outcomes (93.7984%),
and 17/17 functions**. All **100 cases** across seven portable suites pass.

The collector now enforces a dedicated-source baseline for every suite. A drop
in covered lines, branches, or functions fails the run; any denominator change
also fails for explicit review. Overlapping source mappings remain independent.
Reports distinguish regression success from the 97% target: none of these seven
dedicated suites currently meets all three 97% metrics. Eleven gate integrity
checks verify baseline acceptance, each metric's coverage-loss and denominator
change rejection, and regression-pass/target-fail separation.

Evidence: `/usr/obj/5BSD-hypertrace-validation/coverage-startup-gated-20261020/`.
The intermediate committed-state run is retained in
`/usr/obj/5BSD-hypertrace-validation/coverage-startup-handshake-committed-20261020/`.
The remaining 16 handshake branch outcomes include defensive checks after
validation and size multiplication overflow on the current 64-bit ABI. No
production guards or denominator entries were removed to raise the percentage.
Architecture and live-kernel coverage remain unproven.

## Execution progress: handshake corruption and boundary coverage

Four new portable ATF cases cover 44 invalid header, open, bound-record, and
terminal-state configurations, plus null arguments, aliasing, out-of-range vCPU
IDs, occupied configuration, cancellation/reset, and all eight nonempty vCPU
record fields. The corruption matrix checks all public state operations reject
invalid input without changing the handshake, external records, or status
output. Rejected destination configurations preserve both handshake and records.

All **99 startup ATF cases** pass. Handshake coverage rises from 323/350 to
**341/350 lines (97.4286%)**, and from 168/258 to **237/258 branch outcomes
(91.8605%)**, retaining **17/17 functions**. No production changes, helper-only
coverage calls, or denominator exclusions were introduced. The branch target
remains unmet; remaining committed-kernel validation and defensive paths need
further examination. This is portable source coverage, not live qualification.

Final fresh profiles, per-case results, source hashes, and clean exports:
`/usr/obj/5BSD-hypertrace-validation/coverage-startup-handshake-boundaries-20261020/`.
The intermediate corruption-only evidence is retained separately in
`/usr/obj/5BSD-hypertrace-validation/coverage-startup-handshake-faults-20261020/`.

## Execution progress: controller failure-atomic validation

Three new ATF cases exercise invalid state fields, individual credential
fields, every byte of a nonempty ticket destination, null/alias rejection,
occupied ownership, and generation exhaustion. Rejected mutations must preserve
both state and ticket bytes. Retiring at the final generation remains terminal
without wrapping the generation counter. All **95 cases across seven portable
suites pass** with clean coverage exports.

Controller coverage improves from 133/145 to **143/145 executable lines
(98.6207%)**, and from 71/114 to **108/114 branch outcomes (94.7368%)**;
all **11/11 functions** remain covered. No production change or denominator
exclusion was used. Other suite measurements remain unchanged.

The six uncovered branch outcomes are now identified: four null/zero-length
checks in the private overlap helper (public callers already reject nulls and
pass fixed nonzero sizes), the private empty-ticket null check (public claim
already rejects null), and the post-authentication non-CLAIMED check. The last
requires a valid authenticated ticket with a nonzero controller ID matching a
validated non-CLAIMED state, while validation requires that state's controller
ID to be zero. These paths remain in the reported denominator; do not call
private helpers with impossible public inputs merely to claim API coverage.
A production simplification would require its own review; this result does not
meet the branch target and is not live-kernel qualification.

Evidence and original-source mappings:
`/usr/obj/5BSD-hypertrace-validation/coverage-startup-controller-faults-20261020/`.

## Execution progress: expanded portable startup baselines

The reviewed offline ATF allowlist now also includes startup handshake,
controller, and entry ownership. All seven suites pass: **92 cases**, including
31 newly measured cases. These execute original production source in portable
userland tests; they do not exercise a live VM, tracing device, or kernel module.
The collector retains normalized error-header attribution and independent
per-binary profiles, source hashes, test results, and warning-free exports.

| Production component | Executable lines | Branch outcomes | Functions |
| --- | ---: | ---: | ---: |
| Startup handshake | 323/350 (92.286%) | 168/258 (65.116%) | 17/17 |
| Startup controller | 133/145 (91.724%) | 71/114 (62.281%) | 11/11 |
| Startup entry ownership | 620/676 (91.716%) | 442/614 (71.987%) | 31/31 |

None of these three components meets the 97% line-and-branch target yet.
Next, derive fault and invalid-transition tests from the uncovered source
branches, including preservation of state on rejected operations. Keep these
portable results separate from deferred kernel and architecture qualification;
do not sum overlapping mode/event mappings from different suite binaries.

Evidence:
`/usr/obj/5BSD-hypertrace-validation/coverage-startup-atf-expanded-20261020/`.
The four previously measured suites were rerun successfully with unchanged
coverage percentages. Compiler, library, daemon, CLI, build/install and guest
coverage remain part of the full goal; this expansion does not close that scope.

## Execution progress: normalized error-macro attribution

The ATF/standalone startup-mode denominator difference is now explained and
repaired in the collector. Standalone compilation records 88 expansions from
the source-tree `sys/errno.h`; the earlier ATF include order inherited system-
header classification and recorded none. Forcing the same source error header
before system headers preserves those expansion mappings in ATF builds too.
No production source or denominator exclusion was introduced.

The normalized run again passes **all 61 ATF cases** with warning-free exports.
Both builds now map **748 startup-mode lines and 650 branch outcomes**, and both
retain 88 error-macro expansions. The corrected dedicated-mode result is
**722/748 lines (96.5241%), 522/650 branches (80.3077%), and 47/47 functions**.
This supersedes the earlier 722/745 line percentage for comparison with the
standalone build; it does not represent lost executed code.

Static helper profile names remain distinct: for example,
`vmm_startup_mode.c:vmm_startup_mode_overlap` versus
`vmm_startup_mode_test.c:vmm_startup_mode_overlap`. Consequently the collector
still reports each binary independently rather than silently combining or
renaming those counters. The mapping-denominator issue is resolved; cross-build
static-helper identity remains an explicit constraint on aggregation.

Evidence, regenerated per-case profiles/results, complete exports and a hashed
before/after attribution comparison:
`/usr/obj/5BSD-hypertrace-validation/coverage-startup-atf-normalized-20261020/`.
This is a measurement repair, not new state-machine coverage or live testing.

## Execution progress: existing portable ATF suite coverage

`tests/startup-atf-coverage.py OUTPUT` now compiles and runs an explicit reviewed
allowlist of four existing portable ATF programs from `tests/sys/vmm`. These
include original production source files directly; no function extraction or
live device/VM operations are involved. The collector compiles suites in
parallel, enumerates each program's cases, checks each ATF result and process
status, requires one profile per case, excludes listing-only profiles, and
exports production mappings separately for each binary. FreeBSD's installed
`libprivateatf-c` provides the harness.

All **61 cases pass**: 10 event, 41 mode, six management-request and four run-
request cases. Dedicated-suite mappings are:

| Source | Lines | Branches | Functions |
| --- | --- | --- | --- |
| startup event | 344/363 (94.77%) | 224/354 (63.28%) | 22/22 |
| startup mode | 722/745 (96.91%) | 522/650 (80.31%) | 47/47 |
| startup management request | 143/146 (97.95%) | 121/160 (75.63%) | 6/6 |
| startup run request | 41/41 (100%) | 41/48 (85.42%) | 4/4 |

These existing suites add state transitions, cancellation, notification and
entry/unwind coverage far beyond the earlier request-only fixture. Figures
remain per binary: no union is claimed with prior standalone shared-object
measurements. In particular, the ATF-included mode source maps 745 lines versus
748 in the standalone build despite identical source hashes. This attribution
variation remains a measurement gap; the three-line difference is not an
approved reduction of the canonical denominator or a waiver. Static-helper
identity across include-based and standalone builds must also be reconciled
before combining counters. Existing standalone request results remain valid
for their own configurations, not replaced by these lower branch percentages.

All exports are warning-free. Exact compile commands, test inventories, per-
case output/status, source/binary hashes, raw profiles and full exports:
`/usr/obj/5BSD-hypertrace-validation/coverage-startup-atf-final-20261020/`.
No whole-kernel or hardware-execution claim follows from these portable suites.

## Execution progress: startup-management validation and status encoding

`tests/startup-management-values.py OUTPUT` compiles the original portable
`vmm_startup_request.c` and its actual `vmm_startup_mode.c` dependency. All
**4,960 checks pass**: management ABI fields and operation-specific constraints,
vCPU-count boundaries, exhaustive small combinations of phase/owner/execution/
lock/count/bootstrap values, reserved status fields, maximum-vCPU limits,
invalid requests, NULL pointers, in-place encoding and forbidden partial/input-
status output aliasing. Successful encodings are compared byte-for-byte against
expected protocol fields; failures must leave output storage unchanged.

The full request source measures **93.8356% lines (137/146), 92.5% branches
(148/160), and 100% functions (6/6)**. Its larger startup-mode dependency remains
visible: **1.8717% lines (14/748), 3.2308% branches (21/650), and 2.1277% functions
(1/47)** in this run. High request-test counts are not evidence that the mode
state machine is covered. All compiled file/header mappings are retained;
none are credited as kernel-dispatch or vCPU-execution coverage.

Export emitted no warnings. Exact original-source build command, source and
binary hashes, individual expected state checks, profiles and per-file metrics:
`/usr/obj/5BSD-hypertrace-validation/coverage-startup-management-final-20261020/`.
Both request and mode component work remain below the 97% target. No live VM,
kernel module, daemon or tracing device was operated.

## Execution progress: portable kernel startup-run validator

`tests/startup-run-values.py OUTPUT` compiles the original
`sys/dev/vmm/vmm_startup_run_request.c` directly as an instrumented shared object
in its portable userspace mode. This source is included by the VMM module build
and arm64/riscv VMM file manifests; the fixture does not compile or operate a
kernel. Independent compilation exposed a missing NULL declaration, repaired
by including `<stddef.h>` inside the existing non-kernel header branch.

All **570 checks pass**: ABI version/size, vCPU and generation bounds, flags,
reserved fields, buffer sizes, adjacent versus overlapping intervals in both
orders, containment, and address wrap at 32-bit and 64-bit limits. Seeded cases
use arbitrary-precision closed-interval arithmetic as the expected-result
model. Every call must leave the input request unchanged. There are no ioctls,
guest memory accesses or vCPU execution in this fixture.

The complete portable source mapping reaches **100% lines (41/41), 97.9167%
branches (47/48), and 100% functions (4/4)**. One branch outcome remains counted
and unexecuted; no denominator exclusions were applied. This meets the numeric
target for this source in this configuration only, not the whole startup
controller, kernel dispatcher or other architecture binaries. Export emitted
no warnings. Source/binary/driver hashes, exact build command, generated cases,
profiles and full export:
`/usr/obj/5BSD-hypertrace-validation/coverage-startup-run-final-20261020/`.

## Execution progress: memory-size sign and overflow repair

The actual-library value suite now includes 29 memory-size parsing cases.
Five failed before the fix: bare negative values and overflowing unsigned
numbers returned success. `-1` produced SIZE_MAX; the unsigned negation of
`-18446744073709551615` became 1 and was then interpreted as 1 MiB. Inputs above
ULONG_MAX also returned the saturated value as a successful parse.

`vm_parse_memsize()` now rejects a leading minus sign after whitespace and
checks ERANGE from `strtoul()` before using its result. Failure leaves the caller
output unchanged. Existing small-unsuffixed-value MiB semantics, hexadecimal
and octal forms, suffixes and valid maximum values remain tested.
All **347 value checks, 607 layout checks, and the full lifecycle/identity/
attestation suite pass** after rebuilding the actual library. No VM memory was
allocated and no kernel or device operation was performed outside the existing
mocked boundaries.

Only fresh post-fix profiles were merged. The full owned-source libvmmapi
mapping is **17.1688% lines (302/1759), 26.5734% branches (190/715), and 16.0305%
functions (21/131)**. The denominator grew with the parser checks; pre-fix
counters are excluded. Export emitted no warnings. Before/after cases, rebuild
log, fresh profiles, exact binary/source hashes and full export:
`/usr/obj/5BSD-hypertrace-validation/coverage-vmmapi-memparse-20261020/`.
The wider coverage objective and live qualification remain incomplete.

## Execution progress: identity replies and attestation capability export

The actual-library lifecycle suite adds **eight identity lookup calls and five
attestation-export calls**, all passing. Identity tests cover NULL arguments,
ioctl failure, zero/out-of-range IDs, zero epochs and valid replies. Failure
must preserve both caller outputs. Attestation tests cover NULL context,
descriptor duplication failure, rights restriction failure, ioctl allowlist
failure and success. The wrapper requires F_DUPFD_CLOEXEC, exactly CAP_IOCTL
rights, and an allowlist containing only VM_GET_ATTESTATION. Failure after
duplication closes the duplicate while preserving the original error; success
returns the restricted descriptor without prematurely closing it.

fcntl and Capsicum syscall boundaries are replaced at link time, so these tests
verify requested restrictions and ownership rather than actual kernel rights
enforcement. LLVM profile-file fcntl calls are passed through only for its
tracked artifact descriptor. An initial fixture run rejected that profile lock
after tests finished; its counters are excluded. The corrected run exits cleanly
with all earlier lifecycle assertions still passing.

Whole-libvmmapi coverage now measures **15.8948% lines (278/1749), 25.1058%
branches (178/709), and 15.2672% functions (20/131)**. The original denominator
and source/binary hashes are unchanged; export emitted no warnings. Evidence:
`/usr/obj/5BSD-hypertrace-validation/coverage-vmmapi-attestation-final-20261020/`.
No live VM, installed daemon, kernel module or tracing device was operated.

## Execution progress: identity-bound destruction and recovery requests

The actual-static-library lifecycle fixture now adds **17 identity API calls**
covering NULL/empty/overlong names, zero/out-of-range VM IDs, zero epochs, the
maximum valid ID/epoch pair, control-open failure, stale-identity rejection and
success. The ioctl wrapper verifies the exact name/VM ID/epoch and zero reserved
fields. Recovery-by-name tests assert O_NOFOLLOW|O_CLOEXEC open flags and prove
no module lookup/load, VM creation or reinitialization occurs. Failed checked
destruction retains the caller's context and descriptors; request-only success
also retains ownership, while successful checked destruction closes both.
Cleanup changes errno deliberately, verifying that recovery preserves ESTALE.

All lifecycle and identity assertions pass. The kernel's identity comparison is
mocked: these tests prove userspace request construction, ownership and error
handling, not actual kernel stale-identity rejection. Device/module boundaries
remain intercepted and no live VM is operated.

Compatible counters increase the unchanged whole-libvmmapi mapping to
**13.7221% lines (240/1749), 22.0028% branches (156/709), and 13.7405% functions
(18/131)**. Original source and library hashes match the prior baseline and
LLVM export emits no warnings. Evidence and exact archive/fixture provenance:
`/usr/obj/5BSD-hypertrace-validation/coverage-vmmapi-identity-20261020/`.
The 97% component objective and live qualification remain incomplete.

## Execution progress: actual-library VM-open lifecycle tests

`tests/vmmapi-lifecycle.py OUTPUT BUILD_PREFIX` now links the actual instrumented
static libvmmapi archive into a fixture using source-tree interfaces. Unlike
`vmmapi-open.py`, this does not extract function text or recreate `struct vmctx`.
All **13 cases pass**, covering invalid names, allocation failure, control/device
open failures, absent VMs, create and destroy-on-close flags, create failure,
failed reopen with rollback, existing-VM reinitialization success/failure,
module lookup/load control flow, descriptor cleanup and preservation of the
original error despite cleanup changing errno.

Link-time wrappers intercept open, close, ioctl, modfind, kldload and the targeted
allocation failure. VM descriptors are fake; no VM device or module operation
reaches the OS. Real open calls are allowed only for validation-artifact paths
so LLVM can write profiles. An initial fixture run rejected the profile write
after the cases completed; that run is excluded. The final run exits cleanly
and retains the expected injected destroy-failure diagnostic.

Compatible original-source profiles now measure the full library at
**11.0921% lines (194/1749), 18.1946% branches (129/709), and 10.6870% functions
(14/131)**. The denominator is unchanged; generated harness code is not counted.
Library and source hashes match the prior baseline and LLVM export emitted no
warnings. Existing extracted-function tests remain separate historical tests;
the new actual-library fixture provides the production-source attribution.

Evidence, exact compile/link command, archive/source/fixture hashes, status and
output, passing profiles and full mapping:
`/usr/obj/5BSD-hypertrace-validation/coverage-vmmapi-lifecycle-final-20261020/`.
Live VM lifecycle semantics and other architectures remain unverified.

## Execution progress: original-object memory-layout testing

`tests/vmmapi-layout.py OUTPUT MEMORY_PICO` links the existing production
`vmmapi_memory.pico` into a thin shared adapter exposing its hidden entry points.
The implementation is not copied or reimplemented in the adapter. All **607
checks pass**, including 512 seeded layouts compared with an arbitrary-precision
Python reference, low/high-memory boundaries, overflow in domain summation,
high-address and both guard additions, host-span limits, NULL/empty inputs,
unchanged output after rejection, and device-memory segment identifier bounds.
No guest memory is mapped and no kernel/VM operation is performed.

The original library mapping accepts the compatible object profiles without
LLVM warnings; library and mapped-source hashes match the earlier value-API
baseline. Combined coverage for `vmmapi_memory.c` is **97.0588% lines (66/68),
96% branches (48/50), and 100% functions (4/4)**. The remaining guards protect
a NULL internal addition destination (production callers pass local addresses)
and a future size_t wider than 64 bits; both remain counted in this amd64
mapping. The branch target is not yet satisfied, and no denominator is reduced.

The full libvmmapi owned-source mapping now measures **5.4889% lines (96/1749),
12.2708% branches (87/709), and 3.8168% functions (5/131)**. This combines the
public-value corpus with the original-object layout corpus; adapter code is
not counted as production coverage. Other library and architecture paths remain
unexecuted. Evidence, source/object/adapter hashes, exact link command, input
cases, raw profiles and full export:
`/usr/obj/5BSD-hypertrace-validation/coverage-vmmapi-layout-20261020/`.

## Execution progress: actual libvmmapi value-API baseline

The full amd64 libvmmapi now builds with coverage in the isolated object tree.
`tests/vmmapi-values.py OUTPUT LIBRARY` calls the actual shared library's memory
redistribution and dirty-result validation APIs; it opens no VM, performs no
mapping or ioctl and runs no guest. All **318 deterministic checks pass**.
The seeded distribution cases check conservation, granularity, positive and
balanced allocations, output bounds and unchanged outputs after rejected
requests. Dirty-result cases check OBSERVE/CLEAR, bitmap byte boundaries,
maximum bitmap size, malformed ABI fields, all reserved bytes, address wrap,
exact buffer sizing and unchanged input structures.

The actual `vmmapi_dirty_log.c` validator mapping reaches **100% lines (30/30),
97.5% branches (39/40), and 100% functions (1/1)**. This does not certify the
kernel producer, ioctl publication or the dirty-tracking system. The memory
file is only **25% lines / 32% branches**, because its hidden layout helpers
have not been exercised by this public-API fixture.

The whole owned-source library mapping remains explicit: **2.6872% lines
(47/1749), 7.7574% branches (55/709), and 1.5267% functions (2/131)**. Unexecuted
VM-control and architecture-specific functions stay in those totals. Existing
extracted-function tests are not credited to this full-library baseline.
Export emitted no warnings. Build log, seeded results, binary/source/driver
hashes, raw profiles, full export and per-file breakdown:
`/usr/obj/5BSD-hypertrace-validation/coverage-vmmapi-20261020/`.
This establishes a further component baseline and exposes its remaining work;
it does not meet the overall 97% objective or change live-test deferral.

## Execution progress: runtime coverage regression gate

The runtime fixture now also covers default helper-path selection with its
link-time open wrapper; the real `/dev/dtrace/helper` is never opened. All
**19 cases pass**. Full runtime coverage is **96.6292% lines (86/89),
97.8261% branches (45/46), and 100% functions (3/3)**. The remaining uncovered
lines are the nonzero `lmid` formatting branch: in this FreeBSD build `lmid`
is initialized to zero and only the illumos build queries another value.
Those lines and the false branch remain in the raw denominator; no exclusion
or production change was made to improve the score.

`drti-offline.py` now automatically checks final-profile presence, merges only
post-destructor profiles, requires warning-free export and exactly one original
runtime-source mapping, and writes `summary.json`. It enforces the attained
86/89 line, 45/46 branch and 3/3 function baseline. Changed denominators require
explicit review; fewer mapped lines cannot silently pass as better coverage.
It also rejects a visibly stale runtime object before testing. Modification
times are a freshness guard, not a substitute for complete build provenance.

Regression acceptance and the 97% target are separate fields. The current
regression gate passes; the overall runtime target is **false** because line
coverage remains below 97%. This does not gate other components or establish
live qualification. Final run evidence and exact driver/object/source hashes:
`/usr/obj/5BSD-hypertrace-validation/coverage-drti-runtime-gated-final-20261020/`.

## Execution progress: runtime lifecycle repair and offline execution

`tests/drti-offline.py OUTPUT RUNTIME_OBJECT` now links the actual instrumented
`drti.o` with loader/device boundary wrappers from `drti-offline.c`. Link-time
wrapping intercepts dlinfo, open, close and ioctl for both constructor and
destructor; no helper device is accessed. The fixture checks call counts,
registration metadata, module names, load-address behavior and generation IDs.

Six pre-fix failures showed cleanup attempting helper opens/removals despite
disabled initialization, loader failure, corrupt DOF, failed open or failed
registration. Production `drti.c` now records successful registration and skips
cleanup unless that registration occurred. All **18 runtime cases pass**,
including corrupt magic bytes, NULL/empty/plain module names, ET_EXEC versus
ET_DYN addresses, quiet diagnostics and cleanup failures. The **28 provider-link
checks also pass** against the rebuilt object. These are mocked-device runtime
tests and offline link tests, not live registration or guest qualification.

LLVM's ordinary exit hook initially captured counters before the runtime
destructor. The fixture now writes a separate fresh `final-*.profraw` after the
cleanup verifier and suppresses subsequent duplicate dumps. Only those final
profiles are merged; premature exit profiles are retained but excluded.
The corrected full runtime mapping is **96.6292% lines (86/89), 95.6522% branches
(44/46), and 100% functions (3/3)**. No denominator exclusions were applied.
This is below the 97% line/branch goal. The initial premature export (80.90%
lines) is superseded for runtime coverage, not evidence of fewer behaviors.

Before/after failures and initial capture diagnosis are retained under
`coverage-drti-runtime-before2-20261020`, `coverage-drti-runtime-after-20261020`
and `coverage-drti-runtime-final-20261020` in the validation root. Current final
profiles, actual-object/fixture/source fingerprints, commands, results and
warning-free export are under
`/usr/obj/5BSD-hypertrace-validation/coverage-drti-runtime-capture-20261020/`.
The earlier zero-runtime baseline is historical; live behavior remains unproven.

## Execution progress: source-built runtime support object

`cddl/lib/drti` now builds with LLVM coverage in the same isolated object tree.
The CLI integration driver requires that object and explicitly passes
`-x syslibdir=<object-directory>` to provider linking. All **28 checks pass**
using this source-built runtime; provenance records its path and SHA-256.
This removes the installed `drti.o` dependency from subsequent provider tests.
No installation or generated-object execution was performed.

Exporting the linked runtime mapping confirms **0/86 lines, 0/44 branch outcomes
and 0/3 functions executed**. These are explicit uncovered runtime paths, not
credited for linking successfully. The object was built and linked but never
loaded or run. Raw mapping, profiles, build log and source/object hashes are at
`/usr/obj/5BSD-hypertrace-validation/coverage-drti-20261020/`.

The inventory now includes this runtime build target: **19 seed manifests,
114 configuration evaluations, zero evaluation failures, 450 distinct resolved
input paths and 246 unresolved/generated input occurrences**. All six runtime
configurations resolve the maintained `drti.c`; generated object installation
still requires staging verification. Refreshed evidence:
`/usr/obj/5BSD-hypertrace-validation/coverage-inventory-drti-20261020/inventory.json`.

Inspection for the next runtime fixture found that `DTRACE_DOF_INIT_DISABLE`
returns early from the constructor but the destructor still attempts to open
the helper device. The environment variable alone therefore cannot safely
isolate runtime tests from the live device. An offline fixture must intercept
both initialization and cleanup device boundaries before executing this code.
Runtime device behavior remains untested; no change to live deferral is implied.

## Execution progress: provider-object generation and relocatable linking

The actual CLI suite now passes **28 checks**. New integration cases take both
C and C++ generated-header consumers through `dtrace -G`, inspect the resulting
ELF `.SUNW_dof` section, extract and verify DOF magic plus provider/probe names,
and combine the rewritten consumer and provider objects with `ld -r`. Undefined
symbol inspection confirms both probe-call and enabled-probe references were
resolved. No generated object, constructor or executable is loaded or run.
Malformed ELF input, missing input objects and missing output directories are
also rejected without a completed output artifact.

The provider linker uses the installed `/usr/lib/dtrace/drti.o`, whose SHA-256
is recorded in the test provenance. This verifies compatibility with that exact
object, not a clean staged runtime-object build or all installed layouts.
Compiler and library binaries remain the matching isolated coverage builds;
`dtrace_open` still enforces NODEV|NOSYS through the test boundary shim.

Compatible library binary/source hashes were checked before merging the latest
passing profiles with the earlier library corpus; exploratory profiles are
excluded. Both exports emitted no warnings. The full CLI mapping is now
**14.4388% lines (458/3172), 12.9518% branches (215/1660), and 15.7143% functions
(11/70)**. The libdtrace-owned mapping is **36.7247% lines (14110/38421),
32.8828% branches (6715/20421), and 49.5812% functions (592/1194)**. These remain
separate component measurements; inline/shared dependencies remain separately
accounted for. Neither component is at 97%.

Evidence: `/usr/obj/5BSD-hypertrace-validation/coverage-cli-provider-20261020/`,
including raw profiles, exact commands, ELF section listings, unresolved-symbol
checks, generated artifacts, runtime-object identity and separate CLI/library
coverage exports. Live probe execution and qualification remain deferred.

## Execution progress: CLI resolver crash and generated-header consumers

The CLI suite now passes **23 checks** (19 CLI commands and four C/C++ consumer
compilation checks). A new missing-value case reproduced SIGSEGV for
`dtrace -e -x resolvers ...`: option parsing called `strchr()` with a NULL value.
The CLI now rejects that argument with `-x resolvers requires a value` and exit
status 1. Valid resolver selections, verbose/flow-indent compile paths, invalid
language dialect and incompatible header/buffered-output modes are also tested.
Core dumps are disabled in the test driver.

Both C and C++ consumers compile the actual generated provider header against
the source-tree `sys/sdt.h`. Undefined-symbol inspection verifies unmangled
probe and enabled-probe references, and both compilers reject an argument of
the wrong type. Consumer objects are not executed; final provider-object
linking and probe execution remain unverified. Header/input hashes and compiler
versions accompany the results.

After rebuilding the CLI, only fresh passing-run profiles were exported, with
no LLVM warnings. The full `dtrace.c` mapping now measures **12.8625% lines
(408/3172), 11.4458% branches (190/1660), and 14.2857% functions (10/70)**.
The denominator grew by the two validation lines. Earlier CLI counters are not
merged with the changed binary. Before/after results, generated objects,
symbol listings, build logs, profiles and provenance are retained at
`/usr/obj/5BSD-hypertrace-validation/coverage-cli-consumers-20261020/`.
The NODEV|NOSYS boundary remains enforced and live qualification stays deferred.

## Execution progress: actual DTrace CLI baseline

The instrumented `cddl/usr.sbin/dtrace` executable now builds in the isolated
coverage object tree against the matching libdtrace and CTF builds. The new
`tests/cli-offline.py OUTPUT OBJTOP` runs an explicit allowlist of compile-only,
header-generation, version and option-error commands. A small preload shim
forwards `dtrace_open()` to the real library with NODEV|NOSYS forced. This is
necessary because `-e` normally attempts device open before falling back; these
tests must not operate tracing devices or trigger module loading. No other API
is mocked, and no daemon, process-control, VM or tracing-execution mode is run.

All **12 actual CLI cases pass**, checking exit statuses and diagnostic/output
fragments: version, conflicting/invalid options, valid/invalid D compilation,
unknown options, invalid buffer size, quiet compilation, undefined functions,
missing scripts, generated provider header and invalid provider name. The
initial supposed-valid provider name ended with a digit; source behavior rejects
that name. The valid fixture was corrected and the digit-suffix rejection was
retained as its own negative test. Only the subsequent passing-run profiles
were used for measurement.

Full `dtrace.c` coverage is **10.8833% lines (345/3170), 9.7708% branches
(162/1658), and 12.8571% functions (9/70)**. This is the whole mapped file,
including the unexecuted runtime paths; it is not narrowed to compile mode.
Inline-header mappings remain in the raw export and library coverage is
separate. LLVM export emitted no warnings. Generated-header content is checked,
but downstream consumer compilation/linking remains to be tested. Build logs,
raw profiles, command output, driver/library/binary hashes, mapped source hashes
and the exported baseline are retained under
`/usr/obj/5BSD-hypertrace-validation/coverage-cli-20261020/`.
This closes the absence of an actual CLI baseline, not its coverage deficit or
live qualification.

## Execution progress: deferred compiler metadata and diagnostic locations

The isolated actual-library pragma suite now passes **53 cases**, adding
immediate/deferred identifier attributes and version bindings, combined deferred
metadata, unused metadata rejection, built-in scope protection, malformed
version/attribute specifications, dependency syntax/class/main-program errors,
unknown directives, include-location transitions and compiler-context option
rejection. Dependency cases avoid provider sysctls, module enumeration and
filesystem library loading. Valid inputs must compile; invalid inputs must
produce the expected diagnostic fragment, including the named source file for
a remapped diagnostic. This tests compilation, not execution of the program.

Binary and all previously recorded source hashes matched before merging the
new passing profiles with the post-fix baseline. LLVM export emitted no
warnings. `dt_pragma.c` now measures **92.0588% lines (313/340), 80.0926% branches
(173/216), and 100% functions (10/10)**. The unchanged libdtrace-owned denominator
measures **33.9736% lines (13053/38421), 31.0367% branches (6338/20421), and
46.5662% functions (556/1194)**. This adds 117 covered lines and 77 branch
outcomes across that mapping; it does not satisfy 97% or alter the deferred live
gate. Evidence and updated test-driver provenance:
`/usr/obj/5BSD-hypertrace-validation/coverage-pragma-metadata-20261020/`.

## Execution progress: pragma diagnostics and compiler crash repair

The new `tests/pragma-offline.py` invokes the actual compiler in separate
NODEV/NOSYS child processes with core dumps disabled and a 30-second timeout
per case. Before the fix, missing provider names, missing attribute components,
and numeric provider names in `#pragma D attributes` caused SIGSEGV. String or
numeric tokens in other provider positions produced misleading unused-pragma
diagnostics. `dt_pragma_attributes()` now validates both provider tokens before
reading their string fields and reports malformed directives through the normal
compiler error path.

All **22 pragma cases pass** after the fix: six malformed provider forms, all
five valid provider attribute components, option errors, unknown D versus
ordinary pragmas, explicit errors, line directives and ignored identifiers.
The suite is included in `elf-library.py`. Fresh runs also pass the ELF and
allocation suite, 33 compiler cases, 289 option cases, 11 actual linker cases
and the CTF relocation boundary fixture. These compile and serialize programs;
they do not execute probes or establish live behavior.

The changed library was rebuilt and all coverage profiles regenerated. No
pre-fix counters were merged. The **236 fresh profiles** export without warnings.
The current libdtrace-owned mapping measures **33.6691% lines (12936/38421),
30.6596% branches (6261/20421), and 46.3987% functions (554/1194)**.
`dt_pragma.c` measures **79.1176% lines / 63.4259% branches / 100% functions**.
The whole-library denominator increased with the validation code; source and
binary hashes, before/after failures, build logs and raw data are retained at
`/usr/obj/5BSD-hypertrace-validation/coverage-pragmas-20261020/`.
The prior inventory/reconciliation predates this source change and must be
regenerated before use with this binary. Generated-source attribution and the
other inventory gaps remain open; these percentages do not certify the whole
HyperTrace system or satisfy the 97% target.

## Execution progress: exact-source coverage reconciliation

`tests/coverage-reconcile.py INVENTORY EXPORT PROVENANCE OUTPUT --arch amd64`
now reconciles an LLVM export against an evaluated inventory configuration. It
requires exact resolved paths and matching recorded source digests; unresolved
inputs, absent mappings, changed source and missing export provenance remain
visible. Duplicate mappings and ambiguous multiple datasets are rejected.
Repeated inputs cannot inflate denominators. Zero mapped executable counts
produce an unknown percentage, not 100%. The report includes per-component
mapped-subset line, branch and function figures and exact 97% comparisons, but
**never grants whole-component or whole-system acceptance** from this seed
inventory. This is groundwork for a gate, not a completed acceptance gate.

The latest actual libdtrace export matches 54 inventory input occurrences with
source digests. Among SRCS, `dt_benchmark.c` has no established mapping (its
implementation is conditional on `__DTRACE_RUN_BENCHMARKS__`); four generated C
inputs and the generated grammar header need attribution. `gmatch.c`,
`dis_tables.c` and `instr_size.c` appear in the export but lack source digests in
the prior libdtrace-owned provenance subset. These are explicitly unverified,
not credited to the matched subset. Other components remain unmapped **in this
particular export**; this does not erase their separate earlier measurements.
The matched-only figures must not replace the prior whole-library mapping
figures or be compared as a changed coverage denominator.

Eleven synthetic integrity regressions pass, including stale-source rejection,
basename collisions, missing/duplicate mappings, generated inputs, wrong
configuration selection, duplicate inventory entries, multiple exports and
below-threshold branches. These validate reporting behavior, not production
coverage. Source digest agreement alone is not build-time provenance; dependency
closure, generated attribution, binary/profile association and deferred live
qualification remain open.

Evidence: `/usr/obj/5BSD-hypertrace-validation/coverage-option-policies-20261020/inventory-reconciliation.json`.
Run the integrity suite with `python3.12 tests/coverage-reconcile-test.py` from
`contrib/hypertrace`.

## Execution progress: expanded build and installed-input inventory

`tests/coverage-inventory.py OUTPUT` now evaluates 18 seed build manifests in
six configurations (amd64, aarch64 and riscv64, each with snapshot enabled and
disabled). It invokes only make variable queries, never build/install or test
targets. The expanded run completed **108 evaluations without errors**, resolving
**449 distinct input paths** and retaining **240 unresolved/generated input
occurrences** across configurations. Those occurrences are not unique files or
coverage denominators. Every resolved input and included makefile has a SHA-256;
the exact commands, expanded variables and diagnostics are retained.

The inventory includes the compiler/library, actual CLI, host/guest daemon and
control tool, bhyve/bhyvectl/libvmmapi, CTF/ELF/process/runtime-linker libraries,
DTrace/HyperTrace kernel modules and both transports. Following the base build
also identified **BSDTrace, tracectl and libtracecmp**; these now have explicit
entries with coverage unestablished. Custom FILESGROUPS capture the BSDTrace
capability bundle and unit manifests, libtracecmp FIDL schema and notices, rather
than losing these installed files by examining FILES alone.

Validation confirmed the capability binary destination and both bundle files,
FIDL schema, architecture-specific kernel source resolution, and ten additional
amd64 bhyve snapshot inputs (including migration TLS and checkpoint sources).
Evaluating snapshot-enabled manifests on other architectures is not a claim
that snapshots are supported there. No VM, device, installed daemon or kernel
module was operated.

Evidence: `/usr/obj/5BSD-hypertrace-validation/coverage-inventory-expanded-20261020/inventory.json`.
This expands the inventory but does not freeze it: recursive LIBADD closure,
service scripts, additional conditional build options, provider modules,
generated-source attribution and actual staged-package manifests remain open.
Build declarations do not establish executable line/branch denominators or prove
an artifact was built. All inventory entries deliberately remain marked
`not-established-by-inventory` until matched with valid coverage evidence.

## Execution progress: policy and compiler-option behavior

The actual-library NODEV/NOSYS option suite now passes **289 cases**. Buffer
policy and resize tests exercise every valid selection from every valid prior
selection, and verify failed updates preserve that selection. Compiler tests
verify empty programs are rejected by default, invalid `empty` option arguments
preserve that behavior, and the valid flag enables empty compilation and remains
enabled after a rejected update. No tracing device or VM was operated.

Compatible passing profiles were merged only after checking the previous
baseline's library SHA-256 against the current binary. Export produced no
warnings. The unchanged libdtrace-owned denominator now measures **32.6539%
lines (12544/38415), 29.9123% branches (6106/20413), and 44.5561% functions
(532/1194)**. `dt_options.c` measures 31.5634% lines and 33.9779% branches.
This remains a partial component baseline, far below the 97% goal; shared
libraries, architecture helpers and live qualification are not included in
these percentages. Raw profiles, merged data, source hashes, binary hash and
results are retained under
`/usr/obj/5BSD-hypertrace-validation/coverage-option-policies-20261020/`.

## Execution progress: profile capture repaired

The coverage goal is now active for the full inventory. The first measurement
repair adds `tests/test-coverage.h`, an opt-in test-only profile writer using a
private file opened before Capsicum. Forked test children reset inherited
counters, write before `_exit()`, and suppress duplicate exit-time writes.
Production sources and sandbox permissions are unchanged.

TLS, receiver and recovery-exchange suites pass both without instrumentation
and with the helper. Verified profiles include one sandboxed TLS process, eight
receiver children (four sandboxed), and 22 sandboxed recovery children. The
repaired receiver mapping is **89.12% lines / 56.38% branches / 100% functions**,
compared with the initial 43.54% / 30.85% below. This is recovered measurement
from existing cases, not new behavioral tests or whole-system qualification.
Evidence: `/usr/obj/5BSD-hypertrace-validation/coverage-capture-20261020/`.

`tests/coverage-run.py` now provides an explicit offline-suite allowlist,
atomic profile counters, compiler-wrapper/provenance recording, fresh-output
requirements, profile-error detection and checked profile merging. Its three
repaired-suite validation run has 2 TLS, 10 receiver and 27 recovery-exchange
profiles with no LLVM profile errors:
`/usr/obj/5BSD-hypertrace-validation/coverage-runner-check-20261020/results.json`.
A collector pass means tests passed and the available profiles merged; it is
not proof every process emitted counters or every production source is mapped.

Example (use a new output path for every run):

```
python3.12 contrib/hypertrace/tests/coverage-run.py \
  /usr/obj/5BSD-hypertrace-validation/coverage-next \
  --suite native-port --suite native-daemon
```

Whole-source compiler/library/CLI instrumentation, extracted-source attribution,
per-binary mismatch resolution, and the rest of the inventory remain open.
The original baseline below is preserved rather than silently rewritten.

## Execution progress: actual compiler/library baseline

A full source-tree libdtrace build now has LLVM instrumentation, using matching
CTF, libproc and librtld_db dependencies in the isolated build tree. This is a
native non-LTO configuration; all generated lexer/parser and analysis/linker
objects were built. Installed libraries were not substituted for the matching
CTF ABI. The offline inspector now includes matching source-tree API headers.
No library was installed and no DTrace device was opened.

Existing actual-library ELF parsing, round-trip, program identity and allocation
failure cases all pass (11 reported cases). Their initial whole-library mapping
was 23.86% lines / 20.15% branches / 34.84% functions. The newly added
`tests/compiler-offline.py` passes 33 language/diagnostic cases using
`NODEV | NOSYS`, and checks successful output DOF headers and size bounds.
It covers arithmetic/bitwise/logical operations, casts/declarations, variables,
arrays, aggregations, formats, predicates and negative syntax/type/arity cases.
This verifies compilation and serialization, not execution semantics.

Combined passing-run coverage of libdtrace-owned mappings is now
**27.25% lines / 23.12% branches /
37.02% functions**. The denominator is
38,407 mapped executable lines and 20,399 branch outcomes,
including generated sources. Architecture helpers and shared dependencies need
separate inventory/coverage; no runtime-device or other architecture claim follows.
This full-build baseline supersedes the small utility-subset percentage for
planning libdtrace work. The HyperTrace linker, dataflow/type analysis and consumer
runtime still have large unexecuted regions; they are not excluded from totals.

Evidence: `/usr/obj/5BSD-hypertrace-validation/coverage-compiler-20261020/`.
`passing-summary.json` records binary/source hashes and metrics;
`passing-profiles.txt` includes the original passing ELF run and the separate
passing corpus profiles, excluding exploratory failed corpus runs.
`passing-coverage.json` supplies per-file/region details. Compiler corpus
provenance records its PID, binary hash and driver hash. Build logs retain the
initial include/dependency failures; successful library-only dependency builds
exclude unrelated libproc test executables, which are not claimed as tested.

## Execution progress: public HyperTrace linker

`tests/linker-offline.py` now exercises 11 actual compile/link/DOF sequences
through `hypertrace_link`, using the full instrumented library. Cases include
constants, arithmetic, conditional/logical flow, thread/clause-local variables,
strings, printf, aggregations and predicates. Each case runs in a separate
process and checks successful linkage plus generated DOF header/size bounds.
The only new boundary mock is an empty `kldnext` module inventory; compiler
and linker logic are not copied or substituted. Handles use NODEV/NOSYS.
No host module inventory, DTrace device or live guest is required.

All 11 cases pass. Merged with the previous passing library/corpus profiles,
the unchanged 38,407-line / 20,399-branch libdtrace-owned denominator now gives
**31.84% lines / 29.11% branches / 43.47% functions**. Per-file progress:

| File | Lines | Branch outcomes |
| --- | ---: | ---: |
| dt_basic_block.cc | 92.94% | 89.13% |
| dt_dfg.cc | 64.91% | 57.78% |
| dt_hypertrace_linker.cc | 39.87% | 37.34% |
| dt_typefile.cc | 38.39% | 27.27% |
| dt_typing.cc | 22.02% | 27.70% |

Evidence: `/usr/obj/5BSD-hypertrace-validation/coverage-linker-20261020/`.
`corpus/results.json` and `corpus/provenance.json` record tests, the exact library
and driver hashes, and the mock boundary. `summary.json`, `coverage.json` and
`passing-profiles.txt` retain metrics, source hashes and the selected profiles.
The preliminary one-program probe is not included in the final profile merge.
The LLVM export has no warnings. This is linkage/serialization coverage only;
real kernel typefiles, guest execution, and repeated-handle/concurrent linker
lifetime behavior still need dedicated evidence. Negative relocation/type
paths and real runtime consumption remain priorities, not exclusions.

## Execution progress: linker relocation boundaries

The actual-library CTF relocation fixture now supports the isolated native
instrumented build with `--native`; the existing sysroot mode remains available.
It still verifies source/object freshness before executing. Added assertions
exercise absent nodes/DIFO/member metadata, empty definition sets, already
relocated nodes, invalid opcodes, zero and maximum aligned member offsets,
preserved destination registers, the exact 16-bit integer-table index boundary,
and missing/zero-length/out-of-range/unterminated typecast symbol tables.
Leading type annotations and nodes belonging to another DIFO are also checked.

The expanded C++ fixture passes with address/undefined-behavior sanitizers,
linked against the actual LLVM-instrumented library. The library itself is not
sanitizer-instrumented in this build, and the private relocation-method fixture
is not an end-to-end program execution test. No production code was changed.
A preliminary test incorrectly assumed unflagged integer insertion deduplicated
values; the source explicitly requires a sharing flag. The corrected test
allocates index 65,535, verifies its encoding, then verifies rejection of 65,536.

Merged passing coverage is now **32.15% lines /
29.35% branches / 43.89% functions** on the
unchanged full libdtrace-owned denominator. The HyperTrace linker file is
**53.42% lines / 46.35% branches**.
Evidence and exact fixture/library hashes are in
`/usr/obj/5BSD-hypertrace-validation/coverage-linker-errors-20261020/summary.json`.
The selected profile manifest excludes the unsuccessful exploratory run.
Remaining linker allocation failures, symbol/type resolution combinations,
concurrent/repeated-handle lifetime behavior and runtime execution remain open.

## Execution progress: public option API and overflow fixes

`tests/options-offline.py` adds 230 actual-library option conversion and
rejection checks under NODEV/NOSYS. They cover binary size suffixes, every rate
unit, frequency notation, numeric/boolean options, exact signed-range limits,
empty/missing numbers, invalid suffixes and negative/overflowing values. Each
rejection must leave the previously stored option value unchanged. The actual
library regression driver now includes both compiler and option corpora.

These tests exposed production defects in `dt_options.c`: unsigned parsing
accepted a large negative string as positive 1, scaled sizes could wrap to zero,
and rates could overflow into negative values. Size parsing also indexed before
an empty string. Parsing now checks for digits, conversion errors and the signed
range before multiplication, and handles empty strings explicitly. Existing
boolean and NULL-option semantics are preserved. No device operation is involved.

The rebuilt library passes the ELF/allocation/identity tests, 33 compiler cases,
all 230 option cases, 11 public-linker cases and the expanded CTF boundary
fixture. Fresh profiles from this corrected build give **32.55% lines /
29.80% branches / 44.30% functions** across
38,415 libdtrace-owned executable lines and 20,413 branch
outcomes. `dt_options.c` itself is **25.66% lines /
28.73% branches**. The denominator changed with the new guards;
old-build profiles were not merged. Many compiler/runtime options remain untested.

Evidence: `/usr/obj/5BSD-hypertrace-validation/coverage-options-20261020/`.
`before/results.json` preserves failing old behavior; `library-tests/` holds the
passing regressions; `summary.json` records current binary and mapped-source
hashes; `passing-profiles.txt` selects only fresh post-fix runs. Live testing is
still deferred, and these percentages do not include uninstrumented components.

## Method and evidence

LLVM source-based coverage (`-fprofile-instr-generate -fcoverage-mapping`) was
added through compiler wrappers to the existing tests without changing
production behavior. Address/undefined-behavior sanitizers remained enabled.
All 145 native suites and 45 daemon suites passed in the instrumented runs.
The separately instrumented, compiled bhyvectl passed all 16 local IPC cases.
No VM, installed daemon, tracing device, or kernel module was operated.

Artifacts: `/usr/obj/5BSD-hypertrace-validation/coverage-20261020/`.
Each collection has raw profiles, merged `.profdata`, LLVM `*-coverage.json`,
per-file/group `*-summary.json`, diagnostics and driver logs. `production-files.csv`
contains nonempty mapped production-file metrics. `provenance.json` records HEAD,
compiler identity and hashes of mapped production sources; this is a dirty
worktree, so HEAD alone is not its identity. `report.py` reproduces the exports.
Test harnesses, generated fixtures and system headers outside the source tree
are separated from the production groups rather than included in their totals.

Run collections are reported separately: the daemon row uses the daemon suite,
the bhyve row uses native suites, and the frontend row uses actual CLI IPC.
Do not sum these denominators: shared files occur in multiple collections and
some are compiled in different configurations.

## Initial measured coverage

These are percentages of mapped executable source in the named test builds,
not percentages of every production path in those subsystems.

| Area | Lines | Branch outcomes | Functions | Scope |
| --- | ---: | ---: | ---: | --- |
| Host daemon | 75.11% | 58.63% | 92.92% | Native-test build, not the installed service |
| bhyve measured code | 78.21% | 63.72% | 82.21% | Compiled source/headers; extracted adapters excluded from this row |
| dtracedctl | 48.06% | 37.88% | 57.14% | Mapped CLI code under component harness |
| bhyvectl, whole mapped frontend | 20.32% | 6.59% | 19.35% | Includes older unrelated VM-control options; only migration IPC exercised |

Selected files identify where the next tests should go:

| File / build portion | Lines | Branch outcomes |
| --- | ---: | ---: |
| migration_session.c | 83.38% | 68.11% |
| migration_tls.c | 91.89% | 65.52% |
| migration_receiver.c | 43.54% | 30.85% |
| pci_virtio_dtrace.c | 85.08% | 65.68% |
| hypertrace.c | 75.98% | 59.33% |
| dtraced_directory.cc | 78.30% | 61.33% |
| dtraced_state.cc | 61.75% | 45.01% |
| dtraced_dttransport.cc | 32.69% | 25.62% |
| dtraced_clientrequest.cc | 84.86% | 66.42% |

`migration_session.c` is compiled without `BHYVE_SNAPSHOT` in the model suite:
its percentage covers the protocol/state-machine core, not the production
adapter block. Production adapters are tested by other extracted fixtures,
whose counters currently point at generated files rather than original sources.

## Measurement gaps that must be fixed first

- No defensible whole-source percentage yet for kernel HyperTrace execution,
  dttransport, the guest virtio driver, libvmmapi, or the compiler/linker/consumer
  parts of libdtrace. Existing extracted-function tests exercise these areas,
  but their generated-file counters cannot establish a full-source denominator.
  Examples missing original-path mappings include `virtio_dtrace.c`,
  `dttransport.c`, `dt_subr.c`, `dt_elf.cc`, `dt_hypertrace_linker.cc`,
  `snapshot.c`, `bhyverun.c`, and `vmmapi.c`. Absence is unmeasured, not a pass.
- libdtrace's directly mapped utility subset is 60.27% lines / 56.25% branches
  (292 lines); DTrace CLI helper headers are 100% / 75.47% (105 lines).
  Neither is a percentage for the library/compiler or DTrace CLI as a whole.
- `DTRACED_NATIVE_TEST`, preprocessor exclusions, mocked operations, and linker
  garbage collection limit the denominator. Full production configuration
  coverage remains unestablished even when a file has a high percentage.
- The Capsicum TLS subprocess reports inability to write its profile after
  sandbox entry. Forked `_exit` paths can also skip profile flushing. They may
  pass functional tests while providing no corresponding counters.
- LLVM reports two missing/mismatched function records in the native export
  (collector-owner destructor and batch_after, both hash zero) and 29 in the
  daemon export. The merged-across-configurations diagnostic attempt reports
  46; it is not used for the table. Preserve these diagnostics. Resolve
  per-binary attribution/unexecuted mappings before calling the baseline a
  certified coverage gate; do not hide warnings or relabel missing counters.
- No live kernel/guest, long-running stress, or architecture-specific runtime
  coverage was collected. Cross-compilation is build evidence only.

## Required end-to-end scope: compiler, tools and shipped integration

The user explicitly requires all HyperTrace components, including the compiler
and tools, in the coverage plan. No compiler/library area is optional merely
because recent work concentrated on migration. The 97% target must be reported
per component, with unmeasured inventory entries visible.

| Component | Required code and behavior | Required test kinds |
| --- | --- | --- |
| D compiler frontend | Lexer/grammar, declarations, identifiers, types, pragmas, diagnostics, preprocessing, parsing and semantic analysis | Valid/invalid language corpus, diagnostic assertions, boundary cases and grammar-aware fuzzing |
| Compiler backend and analysis | DIF code generation/assembly, analysis, basic blocks, dataflow, type propagation, register/stack handling and architecture assumptions | Golden/generated instruction checks, differential/regression tests, malformed intermediate representations and bounded fuzzing |
| HyperTrace linker and artifacts | HyperTrace linker, linker helpers, ELF/DOF encode/decode, relocation, symbol resolution, metadata, object bounds and program validation | Real compile/link round trips, malformed/truncated object corpus, relocation/overflow tests, allocation and I/O fault injection |
| libdtrace runtime | Open/configuration/options, program lifecycle, probe/provider/module lookup, transport, consumers, aggregation, buffer management, formatting and shutdown | Public API tests using actual library builds, lifecycle/error cases, resource accounting, concurrency and process integration |
| DTrace CLI and tools | Actual dtrace executable, compile/link modes, options, scripts, listing, diagnostics, output, exit statuses and signal handling; compiler artifacts used by base builds | Executable-level tests with stdout/stderr/status assertions, installed-layout smoke tests and upstream applicable regression corpus |
| Host and guest daemons/control tools | dtraced and dtracedctl, daemon startup/configuration, discovery, authorization, delivery, collector lifecycle, reconnect and journals | Component plus process-level tests, protocol fuzzing, failure/restart tests and resource/concurrency checks |
| bhyve and VM tools/libraries | HyperTrace connector/device, snapshots, migration, retirement/recovery, bhyvectl and libvmmapi interfaces | Full-source adapter tests, executable IPC tests, fault injection and separate matched VM integration |
| Kernel and guest support | DTrace/HyperTrace execution and validation, guest memory access, dttransport, virtio-dtrace, identity/authorization, IRQ/ring/queue and packet provenance paths | Kernel-interface tests, portable logic harnesses, architecture variants, then separately authorized live guest/device tests |
| Shared dependencies and installed interfaces | CTF/type information, ELF and process/symbol interfaces used by HyperTrace; public headers, ABI/wire layouts, provider definitions, runtime support objects, loader paths, configuration and service scripts | Dependency/API compatibility tests, cross-build/install-stage checks, ABI/layout tests and staged-package smoke tests |
| Build and packaging | Build options, supported architectures, generated lexer/parser/error tables, native/cross DTrace tools, link-time probe generation and installed files | Clean configuration builds, generated-file reproducibility and staging/package manifest verification |

Generated compiler sources must be attributed back to maintained lexer/grammar
sources where supported, with generated-code accounting separately visible.
Existing upstream DTrace tests must be inventoried and classified as compile-only,
mockable runtime, privileged device, or live-kernel/guest tests before execution.
A test's existence in the tree is not evidence it ran or contributed counters.

The libdtrace compiler/library build inventory is seeded from
`cddl/lib/libdtrace/Makefile` in `coverage-compiler-inventory.json`. It records
all declared SRCS, including generated and externally resolved inputs. This is a
starting inventory, not a complete transitive dependency or installed-tool list.
The next measurement pass must build and instrument the actual compiler/library
and CLI, rather than infer their coverage from the small helper subset in the
initial baseline. Expand the shipped-tool inventory from build/install manifests
and follow each program's library and kernel interfaces before freezing scope.

## Proposed 97% acceptance contract

Target **at least 97% executable lines and 97% branch outcomes in each agreed
HyperTrace component**, with function coverage reported and targeted at 97%
too. Do not substitute an overall average or test-pass percentage. Maintain
separate AMD64, ARM64 and RISC-V/configuration inventories where behavior differs.

First freeze the production file/function inventory, including code reached
through libraries, guest drivers, VM lifecycle adapters and command frontends.
Track every inventory item as instrumented, uninstrumented, unsupported or
excluded with an explicit rationale. Never silently drop hard-to-test code.
For existing mixed-purpose files, publish both HyperTrace-specific function
coverage and whole-file coverage; obtain agreement on scope before using the
smaller denominator as the target. Old continuity/reference paths remain in
raw measurements unless a scope decision explicitly excludes them.

Keep raw figures visible even if justified unreachable branches are separately
reported. A waiver is not an executed branch. Require explicit invariant tests
for every retirement/authorization/recovery boundary regardless of the numeric
coverage score; 97% coverage alone does not establish correctness.

## Work plan, ordered by dependency and risk

1. **Reliable measurement and inventory.** Add a maintained coverage mode with
   per-binary profile association, stable source hashes and reproducible exports.
   Replace copied-function attribution with original-source compilation where
   feasible; otherwise use verified source line mappings plus an independent
   inventory of omitted code. Make profile output work with preopened descriptors
   in sandboxed tests and flush children explicitly in test-only code. Resolve
   mismatch diagnostics and add a gate for missing profiles. Deliver comparable
   per-component baseline reports before chasing percentage increases.
2. **Migration, restore and retirement.** Exercise real production adapters
   with injectable VM/kernel boundaries, not only model operations. Add cases
   from uncovered regions for every quiesce/rollback outcome, interrupted
   persistence, controller ownership collision, resume uncertainty, listener
   shutdown and context lifetime. Cover negative TLS credential/peer/timeout
   paths and keep exact retirement-before-RELEASE assertions. Receiver branch
   coverage is especially low and needs child-process profile attribution first.
3. **Daemon lifecycle and transport.** Prioritize `dtraced_dttransport.cc`,
   `dtraced_state.cc`, then directory/journal and job/client-request paths.
   Exercise connection teardown/reconnect, backpressure, process/reaper proof,
   allocation failures, short I/O, interrupted fsync/rename/unlink, corrupt or
   stale journals and late ACKs. Introduce deterministic scheduling for races;
   keep a small process-level test of the real daemon loop in a disposable
   directory, with device/network boundaries injected, separate from live tests.
4. **Library, compiler and frontends.** Establish complete coverage mappings for
   libdtrace parser/linker/ELF/consumer paths. Use malformed/truncated inputs,
   allocation failures and bounded fuzz corpora with explicit outcomes. Expand
   actual CLI parser/IPC cases and isolate HyperTrace options from legacy VM
   controls without concealing whole-file metrics. Add subprocess tests for
   exits, broken pipes, malformed replies and retained ownership after timeout.
5. **Kernel, guest and device paths.** Compile the actual portable state logic
   against controlled kernel/ring/I/O interfaces. Exercise ring exhaustion,
   descriptor validation, reset/rekey/stop races, stale identities, authorization
   denial and old-buffer discard. Measure all supported architecture branches
   separately. Retain a distinct live-coverage gate for IRQs, DMA, kernel lifetime,
   real guest execution and host/guest boundaries; offline mocks cannot close it.
6. **Raise and enforce thresholds.** After valid baselines, use intermediate
   gates of 85% lines / 75% branches, then 93% / 90%, then 97% / 97% per
   component. Select additions from uncovered source branches, not desired test
   counts. Run sanitizer, concurrency and bounded fuzz tests alongside coverage.
   Add branch-aware regression gates so new code cannot reduce the attained
   threshold. Live qualification stays pending until separately authorized.

For scale only, on the current *partial* denominators the daemon needs another
6,593 covered lines and 8,353 covered branch outcomes to reach 97%; the measured
bhyve group needs 1,965 lines and 2,544 branch outcomes. These are not test counts
or effort estimates. Complete inventory/profile repairs may change both totals.
No calendar estimate is credible until step 1 establishes those denominators.

## Decision

Proceed with the measurement/inventory work first, then risk-ordered test
expansion. The initial runs show substantial branch-coverage work remains.
Do not claim 97% for HyperTrace, or close the deferred live qualification gate,
from these partial component measurements.

## Execution progress: trace-buffer ingestion (2026-10-21)

`consume-ingestion.py` adds the first test of trace-buffer ingestion. Its
harness (`consume-ingestion.c`, ASan/UBSan) opens the actual instrumented
libdtrace with `dtrace_vopen()`, the documented non-device backend. The vector
models the FreeBSD dtrace(4) ioctl interface: it parses the DOF the library
submits and applies the kernel layout rules from `dtrace_ecb_action_add`,
`dtrace_ecb_aggregation_create` and `dtrace_ecb_resize` (including shared
per-description action lists and tuple scratch offsets). It returns BUFSNAP and
AGGSNAP data in kernel format, including switch, ring
(`dtrace_buffer_reserve` wrap and `dtrace_buffer_polish`) and fill policies,
EPIDNONE padding, drops, STATUS, DOFGET, DRAINABLE and the handle-lifetime
ioctls. D clauses are not executed: each case scripts firings with explicit
record values, and expected output is written from documented D formats, not
captured from the library. The model is not the kernel; DIF execution, the
device, guests and transport remain untested by this suite.

48 cases pass. They cover BEGIN/END CPU ordering (including the same-CPU
interposition), temporal ordering, ERROR records, drops, ring wrap, fill, exit,
printf, callback abort/invalid/skip, unknown EPIDs, keyed and keyless
aggregations merged across CPUs, quantize/lquantize/llquantize, all eight
`dtrace_aggregate_walk_*` orders and the aggsort options, joined and default
printa, normalize/trunc/clear records, setopt records, flowindent, stack/sym/mod
symbol resolution (symbol, exact, module-only and unknown addresses), tracemem
dumps, the `dtrace_work` loop, structured (libxo JSON) output validated as
parsed JSON by the driver, `dtrace_consume_quiesced` success and every refusal
(ring, temporal, aggregation, speculation, stopped, flush failure, inactive,
NULL arguments), `dtrace_work_detached`, `dtrace_output_discard`, and
`dtrace_handle_identity`/`dtrace_handle_retired` validation of malformed kernel
answers with outputs left untouched.

Findings, none changed in production code:

- `dtrace_aggregate_walk_valvarsorted`/`valvarrevsorted` abort the consumer
  when aggregations of different actions or key counts are present:
  `dt_aggregate_valcmp()` asserts both. Option-driven sorting never selects
  these comparators, and no in-tree caller uses them. This is inherited
  upstream behaviour; the walk cases therefore use two sums.
- `dtrace_work_detached()` cannot succeed. It proceeds only on
  `DTRACE_STATUS_INACTIVE`, which occurs only before `dtrace_go()`, and
  consumption then refuses the inactive handle with EINVAL. Nothing in
  libdtrace clears `dt_active`. There is no in-tree caller. The test records the
  current behaviour; the intended semantics need a decision.
- A failed `setopt()` record reaches the error handler with a doubled newline
  (`dt_setopt` message wrapped by `dt_handle_liberr`). Inherited and cosmetic.
- Structured output emits the printf message followed by each consumed argument
  as a raw value. Upstream oformat tests check only validity; the case pins the
  current output.

Combined refresh, `coverage-library-consume-20261021` (12 suites, 777 fresh
passing profiles, source and binary hashes verified, empty merge/export logs,
same denominators as `coverage-library-refresh-final-20261021`):

| Denominator | Lines | Branches | Functions |
| --- | ---: | ---: | ---: |
| Complete mapped library object | 19,218/41,958 — 45.80% | 9,005/21,851 — 41.21% | 802/1,362 — 58.88% |
| `/libdtrace/` path subset | 19,175/38,455 — 49.86% | 8,994/20,457 — 43.97% | 797/1,194 — 66.75% |

| File | Lines before → after | Branches before → after |
| --- | ---: | ---: |
| `dt_consume.c` | 501 → 1,572/2,882 (54.55%) | 212 → 735/1,544 (47.60%) |
| `dt_aggregate.c` | 12 → 686/1,298 (52.85%) | 2 → 307/731 (42.00%) |
| `dt_work.c` | 0 → 170/277 (61.37%) | 0 → 102/192 (53.12%) |
| `dt_map.c` | 23 → 240/304 (78.95%) | 11 → 132/194 (68.04%) |
| `dt_handle.c` | 37 → 189/285 (66.32%) | 8 → 42/106 (39.62%) |
| `dt_pq.c` | 0 → 69/85 (81.18%) | 0 → 17/26 (65.38%) |

Remaining consumer gaps: structured output for histograms/stacks, aggpack and
agghist, user stacks and symbols (libproc), `print()` (`dt_print.c`, 0%),
printm, immstack, freopen/ftruncate, setopt handlers, allocation failures and
malformed descriptors from the kernel. No component is near 97%.

### Ingestion follow-up (same day)

The suite now has 77 cases. Additions: 27 injected kernel failures (ENABLE and
GO errno mappings including the vector-only ENOTTY tolerance, DOFGET, EPROBE
and its multi-record re-query, PROBES, FORMAT, BUFSNAP/AGGSNAP EFAULT/EIO and
ENOENT-as-absent-CPU, AGGDESC, STATUS, STOP); structured output for
histograms, avg/stddev, sym/mod and stack keys, principal-buffer
stack/sym/mod/tracemem and printa (`oformat2.json`, checked as parsed values);
and typed `print()` of a D-declared structure.

Further findings, not changed in production code:

- In text mode, `dt_print.c` writes structure text to the caller's stream but
  values with `xo_emit()`, which go to libxo's output (stdout unless
  `dtrace_set_outfp()` was called). `dtrace(1)` calls `dtrace_set_outfp()` only
  for structured output, so `dtrace -o file` with `print()` writes the skeleton
  to the file and the values to stdout. Inherited from the upstream oformat
  change; the case points libxo at the stream to test rendering.
- D-declared bit-fields do not pack like C: libctf rounds each member to the
  next byte and its type's alignment, so `unsigned int lo:3; unsigned int hi:5`
  places `hi` at bit 136. Documented upstream behaviour (kernel CTF is
  unaffected); the fixture follows it.
- `dt_epid_add()` does not check record offsets and sizes against
  `dtepd_size`, and `dt_consume_cpu()` does not check that a record fits in
  `dtbd_size` (after `dt_realloc_buf()` shrinks the allocation). Not reachable
  with kernel-produced buffers, and no production consumer supplies
  `dc_get_buf`; worth hardening before any guest-originated buffer is consumed
  directly. The library is not sanitizer-built, so no over-read test was added.
- The vector contract permits NULL `GElf_Sym` and NULL `dtrace_syminfo_t` in
  `dtv_lookup_by_addr` (native lookup accepts both; `dt_aggregate_sym` passes a
  NULL syminfo). Recorded for any future vector backend.

Suite-only measurement (`consume-ingestion-dev-cov3`, not a combined refresh):
`dt_consume.c` 1,737/2,882 lines (60.3%), `dt_work.c` 189/277 (68.2%),
`dt_map.c` 269/304 (88.5%), `dt_print.c` 225/421 (53.4%), `dt_aggregate.c`
712/1,298 (54.9%).

## Execution progress: HyperTrace linker corpus and a linker crash fix (2026-10-21)

`linker-corpus.py` links 67 valid D programs through `hypertrace_link()`
(operators, every variable scope and kind, built-ins, 23 subroutine groups,
actions, aggregations, histograms, printa and its companions, stacks and
symbols, translators, casts, D `if`/`else`). Each case runs in its own process,
because `dt_set_progerr()` terminates the consumer on a typing error. A case
passes only if it links with an empty message and yields DOF accepted by
`dof_validation.py`. The cases use NODEV with the host kernel's CTF read from
`/boot/kernel/kernel` (hash recorded in provenance); no device, module load or
VM is used. Linking intentionally changes DOF (type data is added), so byte
identity with unlinked DOF is not used as an oracle.

**Production fix.** The first corpus probe crashed `hypertrace_link()` with
SIGSEGV on `BEGIN { trace(strlen(execname)); }` when no kernel type file was
available (the empty module inventory used by `linker-offline.py`; equally a
host whose kernel CTF cannot be loaded). `TypeInference::inferSubr()` assigned
`dt_typefile_kernel()` and guarded it only with `assert()`, which the C++
objects compile out, then dereferenced NULL in `Typefile::getCtfID()`
(backtrace from the core: `dt_typing_subr.cc:399`, `inferDIFO`,
`HyperTraceLinker::processDIFO`). `dt_typing_subr.cc` now reports
"<subr>: kernel type information is unavailable" through `dt_set_progerr()` and
returns the existing typing failure. Two `no-kernel-ctf` cases under the empty
inventory check the reported error (exit 1 with the message) and that a
program without subroutines still links. The development library was rebuilt
with the recorded command (`typing-null-kernel-lib-rebuild-20261021.log`).
`dt_set_progerr()` terminating the calling process is unchanged imported
design; whether library callers should instead get an error return is open.

Combined refresh, `coverage-library-linker-20261021` (13 suites including
`consume-ingestion` and `linker-corpus`, 1,053 fresh passing profiles, hashes
verified, empty merge/export logs). The denominators grew by the five fixed
lines.

| Denominator | Lines | Branches | Functions |
| --- | ---: | ---: | ---: |
| Complete mapped library object | 21,864/41,963 — 52.10% | 10,233/21,853 — 46.83% | 879/1,362 — 64.54% |
| `/libdtrace/` path subset | 21,821/38,460 — 56.74% | 10,222/20,459 — 49.96% | 874/1,194 — 73.20% |

| File | Lines (previous refresh → now) | Branches |
| --- | ---: | ---: |
| `dt_hypertrace_linker.cc` | 406 → 598/760 (78.7%) | 216 → 331/466 (71.0%) |
| `dt_dfg.cc` | 468 → 615/721 (85.3%) | 386 → 507/668 (75.9%) |
| `dt_linker_subr.cc` | 203 → 262/343 (76.4%) | 145 → 195/274 (71.2%) |
| `dt_typing.cc` | 344 → 589/1,562 (37.7%) | 254 → 388/917 (42.3%) |
| `dt_typing_subr.cc` | 0 → 371/631 (58.8%) | 0 → 141/238 (59.2%) |
| `dt_typing_var.cc` | 72 → 219/668 (32.8%) | 104 → 151/408 (37.0%) |
| `dt_typefile.cc` | 143 → 227/336 (67.6%) | 50 → 84/154 (54.5%) |

The remaining typer gaps are mostly internal-invariant refusals and
guest-relocation paths that need guest CTF. No component is at 97%.

## Execution progress: options, tagged diagnostics and an enumerator fix (2026-10-21)

`options-properties.py` checks 160 option cases through `dtrace_setopt()` /
`dtrace_getopt()`. Expected values follow the documented grammar: binary
k/m/g/t size suffixes with overflow at the INT64 boundary, ns..day and hz
rates, yes/no-style switches and non-negative integers, and case-sensitive
enumerations. Every refusal must leave the previous value unchanged. Compile
options cover accepted values and refusals and confirm they are unreadable
through getopt; pragma cases cover options refused inside a D program.

`compiler-diagnostics.py` compiles 148 invalid programs with
`DTRACE_C_ETAGS` and requires the exact `[D_TAG]` for each, so each rejection
is checked for its documented reason rather than any failure. Not reached from
plain D in this configuration: D_DECL_MNAME (anonymous members are a syntax
error first), D_OP_ACT (type checks pre-empt it), D_FUNC_IDENT (needs a kernel
data symbol), D_DECL_IDENT, D_OP_IDENT, D_OP_DYN and D_ARGS_IDX (need probe
arguments or other contexts), and D_CLEAR/NORMALIZE/TRUNC/PRINTA_AGGBAD (an
aggregation must exist in this generation without being assigned). These
remain uncovered diagnostics, not proven dead code.

**Production fix.** `dt_decl_enumerator()` computed the implicit value
`ds_enumval + 1` in `int` before knowing whether it was needed, so an
enumerator after INT_MAX was signed-overflow undefined behaviour and silently
became INT_MIN (`enum e { A = 0x7fffffff, B }` compiled). The explicit-value
path already raised D_DECL_ENOFLOW. The implicit value is now computed only
when no initializer is given and is refused with the same diagnostic at
INT_MAX. The D_DECL_ENOFLOW case is the regression. Rebuild log:
`enum-overflow-lib-rebuild-20261021.log`. This is inherited upstream code.

Combined refresh `coverage-library-diag-20261021`: 15 suites, 1,061 fresh
passing profiles, hashes verified, empty merge/export logs.

| Denominator | Lines | Branches | Functions |
| --- | ---: | ---: | ---: |
| Complete mapped library object | 22,810/41,969 — 54.35% | 10,667/21,855 — 48.81% | 907/1,362 — 66.59% |
| `/libdtrace/` path subset | 22,767/38,466 — 59.19% | 10,656/20,461 — 52.08% | 902/1,194 — 75.54% |

Notable files: `dt_parser.c` 2,385/3,678 (64.8%), `dt_cc.c` 1,355/1,731
(78.3%), `dt_decl.c` 561/717 (78.2%), `dt_options.c` 474/678 (69.9%).

Also noted, not changed: with HyperTrace enabled, `dtrace_setopt()` records
option strings in process-global `dtelf_*opts` tables shared by all handles in
the process.

## Execution progress: program-ELF options and an option-record fix (2026-10-21)

`elf-options.py` sends options from host to guest in program ELF. A host
handle with HyperTrace enabled sets eight runtime options plus `zdefs` and
`define` and writes the program with `dtrace_elf_create()`. A
`dtrace_set_guest()` handle parses it and must read back every runtime option
with the host's value. A non-guest parse must leave options unchanged, and
three malformed option records (oversized length, unterminated name,
unterminated argument) must be refused with "invalid option name, length or
argument" before any option is applied. Each scenario runs in its own process
because option strings live in process-global tables.

**Production fix.** The first run crashed `dtrace_elf_create()` in every
scenario. In `HyperTraceELFParser::createElfOptions()`, all three option loops
copied the cpp flag of `define`, `incdir` and `undef` with
`strlcpy((char *)eop->eo_option, ...)`, which uses the 64-bit field's *value*
as the destination pointer. The compile-time loop zero-allocates records, so it
wrote through NULL: any HyperTrace program built with `-D`, `-I` or `-U`
crashed ELF creation. The runtime and dynamic-runtime loops also allocated
records with `malloc()`, so the unused bytes of each 64-byte name field
carried uninitialized heap contents into an ELF that crosses the host/guest
boundary. Every record was also leaked after being copied. All three loops now
copy into `&eop->eo_option`, the runtime loops zero-allocate, and each record
is freed after copying (error paths still leak the record; noted, unchanged).
Rebuild log: `elf-options-lib-rebuild-20261021.log`.

Combined refresh `coverage-library-elfopt-20261021`: 16 suites, 1,081 fresh
passing profiles, hashes verified, empty merge/export logs.

| Denominator | Lines | Branches | Functions |
| --- | ---: | ---: | ---: |
| Complete mapped library object | 23,015/41,972 — 54.83% | 10,775/21,855 — 49.30% | 909/1,362 — 66.74% |
| `/libdtrace/` path subset | 22,972/38,469 — 59.72% | 10,764/20,461 — 52.61% | 904/1,194 — 75.71% |

`dt_elf.cc` 1,709/2,568 lines (66.5%); `dt_options.c` 500/678 (73.7%).

## Execution progress: x86 instruction-length differential (2026-10-21)

`instr-size-differential.py` compares `dtrace_instr_size_isa()` (the
kernel-portable `dis_tables.c` decoder linked into libdtrace; pid/fasttrap
probe placement depends on it) with LLVM's disassembler. It covers up to
300,000 instructions from the start of `.text` in `/bin/sh`,
`/lib/libc.so.7`, `/usr/bin/awk`, `/boot/kernel/kernel` and the libdtrace
under test, with binary hashes recorded. Each instruction is decoded in place,
with its real following bytes, in the LP64 model.

Oracle handling: `llvm-objdump -z` (no zero-run elision); prefixes that LLVM
prints alone on a line are folded into the next instruction; instructions LLVM
cuts short at a symbol start (padding before a function) are counted
separately; LLVM `<unknown>` entries are skipped. A decoder refusal (-1) is
reported as unsupported, never as agreement.

Result: 919,045 instructions agree, with no length disagreements. The only
refusals are `rdpkru`/`wrpkru` (`0f 01 ee`/`0f 01 ef`) in libc, which the
decoder tables predate. This is a safe gap (no probe can be placed there, and
nothing is mis-sized), but a pid probe on those instructions is unavailable.
The 2 symbol-boundary and 1 LLVM-unknown skips are in the kernel's padding.

Combined refresh `coverage-library-instr-20261021`: 17 suites, 1,085 fresh
passing profiles, empty merge/export logs. Complete mapped library object:
**23,888/41,972 lines (56.91%), 11,406/21,855 branches (52.19%), 922/1,362
functions (67.69%)**. `dis_tables.c` 847/1,805 lines (46.9%); the remainder is
mostly operand-text formatting, which the size path does not use.
`instr_size.c` 26/32.

## Library fixes for earlier findings (2026-10-21)

Fixes for findings recorded above, each with a regression case:

- **`print()` text output split across streams (fixed).** `dt_print.c` now
  emits values through a per-call libxo handle (`pa_xo`). In text mode
  `dtrace_print()` binds it to the caller's stream with
  `xo_create_to_file(fp, XO_STYLE_TEXT, XOF_FLUSH)`, so values and structure
  text share one ordered stream. Structured output keeps libxo's default
  handle (NULL). `print-typed` now checks the caller's stream without
  redirecting libxo.
- **Value-first walks aborted on mixed aggregations (fixed).**
  `dt_aggregate_valcmp()` orders entries by key count and then aggregating
  action before comparing values, instead of asserting both are equal.
  `walk-valvar-mixed-kinds` walks a count and a sum value-first and in reverse.
- **Doubled newline in setopt errors (fixed).** `dt_setopt()`'s message no
  longer ends in a newline, matching the other `dt_handle_liberr()` callers.
- **`dtrace_work_detached()` removed.** It was imported unused from CADETS. It
  could not succeed once `dtrace_consume` began refusing inactive handles, and
  it had no callers.
- **Program-ELF option records on error paths (fixed).** Each record in
  `createElfOptions()` is now owned by a scope guard, so error returns no longer
  leak it.

Not changed: `dt_set_progerr()` still terminates the calling process. The
rework (record the error and unwind to `hypertrace_link()` with a C++
exception, with guest forwarding moved into an exported function called by
`dtrace(1)`) was not applied in this session.

Rebuild log `library-fixes-rebuild-20261021.log`. Refresh
`coverage-library-fixes-20261021`: 17 suites pass, 1,085 fresh profiles;
complete mapped object 23,876/41,966 lines (56.89%), 11,402/21,861 branches
(52.16%), 921/1,361 functions.

## Execution progress: user/guest symbols, packed output and the dtraced client (2026-10-21)

`consume-ingestion` now has 87 cases. New ones cover:

- vector-mode user stacks, uaddr, usym and umod;
- a guest-tagged user stack (`[guest vmid=7 pid=42]` header) and guest uaddr
  (`guest[7]:pid[42]`0x…`);
- a guest kernel stack (`guest[9]`0x…`, with the record argument encoded as
  `dtrace_ecb_action_add()` does for a VM probe);
- `immstack()` pre-symbolized frames (the model now sizes IMMSTACK and
  PRINTIMMSTACK by the kernel's host rule);
- agghist in ASCII and UTF-8, with bars of round(value*40/total), and aggpack
  checked structurally under encoding=ascii;
- printm, the BEGIN-only error interposition when stopped with BEGIN and END on
  one CPU, denormalize, and the default NULL callbacks (probes consumed,
  records skipped, buffers drained).

`dtraced-client.py` tests libdtrace's side of the dtraced protocol. The peer
decodes frames with the daemon's production `dtraced_wire_decode_header()` and
`hypertrace_envelope_decode()`. Program source IDs are recomputed with libmd
SHA-256. 62 checks in six process-isolated scenarios:

- framing with acknowledge, NACK (EPROTO) and peer-close, plus
  shutdown-on-failure and argument refusals;
- ELF delivery with and without identity, and program-less forwarding;
- location, size, empty-file and non-regular-file refusals;
- the HyperTrace VM envelope on outbound guest-bound programs (none inbound),
  with ESTALE for an out-of-range VM or zero epoch;
- the async queue: worker delivery, unlinking its temporary file, and
  idempotent teardown;
- the terminal discard fence (ESHUTDOWN);
- the consumer handshake: exact `dtrace-<pid>-<hex>` identity, random nonzero
  session IDs that persist across reconnects, a foreign server hello (EPROTO),
  early close, no daemon, and four malformed kernel birth identities (EPROTO).

Two audited boundaries apply. `connect()` is interposed only for
`DTRACED_SOCKPATH`, redirecting it to a socket in the test directory. A
preloaded shim answers `pdself()` and `PDIOC_GET_BIRTH_IDENTITY`, because the
host's capability policy refuses `pdself()` to the test ("Capabilities
insufficient"). The harness ignores SIGPIPE, as `dtrace(1)` does.

**Interoperability defect found and fixed (daemon component).**
`dtraced_wire_decode_header()` required a canonical NUL-terminated string in
`elf.ident` when `ident_present == 1`. libdtrace's program identity is 128
random bytes (`dt_program.c` `arc4random_buf`), and `dtraced_clientrequest.cc`
itself handles it as raw bytes. As a result, practically every identity-bearing
ELF frame (`dtrace.c` non-host outbound path) would have been refused with
EPROTO. Reported to the daemon agent, which changed the decoder to accept a
binary identity when present and still require zeros when absent; the client
suite now passes against it. See COVERAGE-daemon.5BSD.md for its regression.

Scope note: `dtraced_wire.h` and `dtraced_io.h` appear in libdtrace's mapping
because their static inline functions are compiled in. Functions only the daemon
calls cannot be reached from libdtrace and are measured in the daemon component.
The libdtrace row includes them only because the mapping does.

Combined refresh `coverage-library-client-20261021`: 18 suites, 1,109 fresh
profiles, hashes verified, empty merge/export logs. Complete mapped object
**24,844/41,966 lines (59.20%), 11,822/21,861 branches (54.08%), 970/1,361
functions (71.27%)**. `dt_consume.c` 2,132/2,882 (74.0%), `dt_subr.c` 788/1,215
(64.9%), `dt_aggregate.c` 839/1,302 (64.4%).

## Execution progress: pid provider probe placement (2026-10-21)

`pid-placement.py` checks pid-provider probe placement, a safety property:
a wrong offset corrupts the traced process. The test builds `pid-target.c`
(-O2, no jump tables). libdtrace creates the target stopped at exec with
`dtrace_proc_create()` (real libproc/ptrace; the target never runs past
exec), gets an inert placeholder fasttrap descriptor, and compiles pid probe
descriptions with ZDEFS. `pid-placement-shim.so` records each
`FASTTRAPIOC_MAKEPROBE` request on that descriptor instead of a kernel. Expected
offsets come from `llvm-objdump`/`llvm-nm` of the same binary: entry at 0;
return at every `ret` and every direct jump leaving the function (tail calls);
`*` adds every instruction boundary; an explicit offset must be a boundary.

All 8 checks pass: `ht_branch` returns at 9/39/43, the `ht_tail` tail-call
jump at 7, all `ht_leaf` boundaries, a function glob, an aligned offset, and a
misaligned offset refused with "offset 0x1 is not aligned on an instruction".
Not yet covered: jump-table functions (where offset probes are suppressed),
shared-library modules via rtld_db, USDT/is-enabled probes, grabbing a running
process, and process-exit notifications.

Combined refresh `coverage-library-pid-20261021`: 19 suites, 1,113 fresh
profiles. Complete mapped object **25,511/41,966 lines (60.79%),
12,062/21,861 branches (55.18%), 1,004/1,361 functions (73.77%)**.
`dt_proc.c` 39 → 332/555 lines, `dt_pid.c` 0 → 204/576, `i386/dt_isadep.c`
0 → 156/264.

## Execution progress: program-verifier mutation and three fixes (2026-10-21)

`program-verify-mutation.py` treats `dt_prog_verify()` as the tamper gate for
programs returned across the host/guest boundary. Each of six programs is
compiled and linked with `hypertrace_link()` (as `dtrace(1)` does before
verifying) and written as program ELF. Every byte is then mutated with three
XOR masks, and each mutant is parsed and verified against the original. The
oracle is `dtrace_program_compiled_digest()`: an accepted mutant must compile
to the same program. Plain program ELF carries no checksum, and an unkeyed one
would not stop a malicious peer, so the verifier is the gate. Children exit
with `exit()` so that their coverage profiles are written.

Result after the fixes below: about 126,000 mutants. About 109,000 were
accepted with an identical digest (padding and unused bytes), 4,798 were
rejected by the verifier and 12,214 refused by the parser. 123 were accepted
with a changed program, all in two documented classes that the driver
reports and does not hide:

- variable-table type sizes (96): the verifier deliberately reconciles
  variable sizes, because relinking for another kernel changes struct sizes.
  Design behaviour.
- DIFO return type when the original's is `DIF_TYPE_BOTTOM` (27): the verifier
  accepts any concrete type for a result left to relinking. **Open design
  gap:** a tampered response can change the kind or by-reference flag of such
  a result. Closing it needs the relinker's type inference in the verifier.

**Fixes (libdtrace, each with this suite as its regression):**

1. **Heap over-read on malformed section names** (`dt_elf.cc`).
   `HyperTraceELFParser::toProgram()` built strings from `elf_strptr()`, which
   does not ensure the name is terminated inside the section-name table. ASan
   reported heap-buffer-overflow reads at `dt_elf.cc:3130` for every corpus
   program. A new `elfSectionName()` returns a name only if a NUL lies within
   the table's data; both call sites use it. This is untrusted input.
2. **Verifier ignored the ECB probe ID** (`dt_program.c`). The kernel enables
   only the named ID when one is given (and the names still match). A returned
   program could therefore narrow a wildcard enabling to one probe and pass
   verification. `dt_prog_verify_inner()` now requires the returned program to
   keep the original's `dtpd_id`. No HyperTrace transformation rewrites it.
3. **Verifier corrupted string sizes when `strsize` was unset**
   (`dt_program.c`). `dt_prog_apply_difo_metadata()` set string-returning DIFO
   sizes to the `strsize` option, which is `DTRACEOPT_UNSET` (0xfffffffe) for
   a consumer that never set it. `dtrace(1)` sets 256 explicitly and was
   unaffected; other libdtrace consumers would have produced programs the kernel
   rejects. Unset now means the library default `_dtrace_strsize`. Declared in
   `dt_impl.h`.

Also noted: verification rewrites the verified program in place (the string
size normalization above) and is idempotent after the first call. Callers
that hash a program must hash after verification.

Combined refresh `coverage-library-verify2-20261021`: 21 suites, 1,125 fresh
profiles, hashes verified, empty merge/export logs. Complete mapped object
**26,260/41,980 lines (62.55%), 12,513/21,877 branches (57.20%), 1,025/1,362
functions (75.26%)**; `/libdtrace/` subset 25,183/38,477 lines (65.45%).
`dt_program.c` 1,152/1,706 (67.5%), `dt_elf.cc` 1,869/2,578 (72.5%),
`dt_analysis.c` 265/459 (57.7%).

## Component record: DTrace CLI and drti (2026-10-21)

Full record: `COVERAGE-cli.5BSD.md` (CLI agent). Summary, verified by the
coordinator against `cov-cli-final-20261021/summary.json`:

| File | Baseline | Final |
| --- | ---: | ---: |
| `dtrace.c` lines | 458/3,177 (14.4%) | 3,008/3,177 (94.68%) |
| `dtrace.c` branches | 218/1,667 | 1,464/1,667 (87.82%) |
| `dtrace.c` functions | 11/70 | 69/70 (uncalled `checkmodref` missing) |
| CLI component total | | 3,108/3,282 lines (94.70%), 1,544/1,773 branches (87.08%) |
| `drti.c` | | 86/89 lines, 45/46 branches (illumos-only `LM%lu` branch unreachable) |

405 executable cases (`coverage-cli-cases.py`) assert exit status and exact
stdout/stderr. They run the real binary behind an audited preload boundary
(`cli-model-shim.c`: model dtrace(4) vector, refused device/kldload access,
fault injection that must fire) and a scripted dtraced (`cli-fake-dtraced.c`),
including a real host↔guest loop and signals. Eight `dtrace.c` defects were
fixed with regressions: a lost wakeup (condition signal versus three waiters,
6/40 hangs before and 80/80 passes after), `-D` ignored, `-g` rejected,
unreachable session-file validation, two format/argument mismatches,
`vm_name == NULL` on an array, and 35 `fatal()` calls with wrong errno text.
Open: a handle-close race when `fatal()` runs while workers use the handle
(6 crashing cases, profiles excluded); drains refused under the CLI's default
`temporal=yes`; the meaning of `-y`; duplicate-delivery and KILL-on-shutdown
behaviour; and fixed `/tmp` templates left behind on failure paths. The
remaining 169 `dtrace.c` lines are mostly dead (`checkmodref`),
benchmark-only, defensive or timing races; about 98% would follow from a scope
decision. Generated compiler sources: `dt_grammar.y` 282/364 and `dt_lex.l`
379/531 attributed lines; `dt_errtags.c`/`dt_names.c` have no line mapping.

Coordinator follow-up fixes in libdtrace, prompted by the CLI agent's
findings:

- `dtrace_sleep()` returned before delivering queued process notifications
  whenever its deadline had passed, so with fast rates `-c` exits were never
  reported. Notifications are now delivered on both paths. The pid lifecycle
  case now runs without a recent status poll and is the regression.
- The zero-probe diagnostic printed HyperTrace's empty target as a fifth field
  (`:nosuch:::probe`). The target and its separator now appear only when a
  target is given. The CLI case was updated.
- `dt_provider.c` kept the previous argument's `dtt_flags` (for example
  userland) when an argument type failed to resolve; the flags are now cleared.

All 405 CLI cases pass against the rebuilt library
(`cov-cli-recheck-20261021`).

### CLI follow-up: fatal() race and temporary files (2026-10-21)

Both open CLI defects above are fixed in `dtrace.c`. All 454 cases pass, with
none ending by a signal (`cov-cli-final6-20261021`).

- **fatal()/dfatal() handle race.** Once a second thread can exist, every
  `g_dtp` user takes `g_dtpmtx`, which is now recursive. `fatal()` is single
  shot (an atomic flag). The winning thread unlinks tracked temporary files,
  then calls `dtrace_close()` under the lock and exits holding it, so no thread
  can use a closed handle. The lock order is `g_pgplistmtx` before `g_dtpmtx`.
  `prochandler()`, which runs under the handle lock, defers its wakeup. No mutex
  is destroyed while it may still be in use. Before the fix, 19 of 80
  repetitions of the eight concurrent `fatal()` cases crashed
  (`cov-cli-race-before-20261021`). After it, 0 of 200 crashed
  (`cov-cli-race-after-20261021`). In that run, 2 of 202 cases still failed:
  two threads' diagnostics interleaved mid-line. Each diagnostic is now
  written in one stdio call, and the final run includes the permanent
  `fix-fatal-race-*` stress group.
- **Temporary files.** All CLI temporary files go through `tmp_mkstemp()`,
  which honours `TMPDIR` except in set-id processes, and are tracked until
  unlinked. `fatal()`, `dfatal()` and `dabort()` unlink any that remain. The
  `-E -e` output is deliberately kept, because printing its path is documented
  behaviour. The runner fails any case that leaves a file behind. Before the
  fix, the 12 failure cases left 9 files in `/tmp`; after it, none did.
- **Changed case.** `host-duplicate-reply-while-busy` is now
  `host-duplicate-reply-after-busy-program`, because serializing handle use
  makes the old interleaving impossible.
- **Coverage.** `dtrace.c` 3,101/3,297 lines (94.06%), 1,494/1,715 branches
  (87.11%), 78/79 functions. The denominators grew with nine new helpers.
- **Driver.** The driver now snapshots the shared libraries into the run
  directory (`libsnap/`) and refuses results if they change mid-run, after
  concurrent library rebuilds invalidated two runs.
- **Test fixtures.** The three `consumer-*` extraction fixtures gained stubs
  for the new helpers (`harness-fixtures.diff`); all 11 extraction harnesses
  pass (`cov-cli-extraction-check3-20261021`).

Coordinator check: the five evidence directories' `results.json` files match
the counts above (454/454; 19 signalled before against 0 after; 14/14 for the
temporary-file cases).

### pid provider, USDT and libproc (coordinator, 2026-10-21)

`pid-placement.py` now has 89 checks (`pid-ext-10-20261021`). It adds
`pid-target-asm.S` (hand-assembled return forms), a USDT executable and a
USDT library built with the instrumented `dtrace -h/-G`, and a CTF target
built as FreeBSD builds do (ctfconvert per object, then ctfmerge). Targets now
use `/usr/bin/cc`: the coverage wrapper had instrumented them, and its
`lock incq` counters broke the objdump oracle (lone prefixes are now merged
in the oracle too). The shim replaces the helper device and answers or refuses
`FASTTRAPIOC_GETINSTR`. The vector counts re-evaluation ENABLEs.

Eight defects fixed, each with a regression check that failed before:

1. **Re-evaluation ENABLE never worked** (`dt_pid.c`). After creating pid
   probes, `dt_pid_create_probes` called `DTRACEIOC_ENABLE` with a NULL
   argument. The ioctl layer copies a `dtrace_enable_io_t` in, so the call
   failed with EFAULT, and retained enablings were never re-matched. The
   late-load path allocated an unused probe buffer and leaked it on every
   rtld event. Both paths now use `dt_pid_rematch()`, which passes a zeroed
   structure with a NULL DOF pointer (the kernel's documented cue). Before the
   fix, the pre-fix library sends the NULL argument (`rematch_null: 1`,
   `pid-rematch-before-20261021.log`).
2. **`dtrace -G` objects forced an executable stack** (`dt_link.c`). The DOF
   object had no `.note.GNU-stack`, so `ld -r` with `drti.o` produced an
   executable-stack note, and lld refuses to link it into an executable. Every
   USDT executable failed to link (`pid-ext-before-20261021`). The 32- and
   64-bit writers now emit an empty, non-executable `.note.GNU-stack`.
3. **libproc reported each object once per mapping** (`lib/libproc/proc_sym.c`
   `proc_iter_objs`). The loop compared each mapping's basename against the
   previous mapping's full path, so the two never matched. Anonymous mappings
   between segments were also passed on as ".". USDT DOF was registered once
   per mapping: four `DTRACEHIOC_ADDDOF` calls for one executable, three of
   them with the base address of a later mapping. A real kernel would have
   placed tracepoints at wrong addresses in the target. Glob module matches
   created duplicate probes, and per-object CTF loading duplicated
   containers. Each object is now reported once, at its lowest mapping,
   identified by the shared `map_info` file; mappings without a file are
   skipped.
4. **The `-` (absolute address) function never created a probe**
   (`dt_pid.c`). The synthesized symbol left `st_shndx` uninitialized, and the
   "defined function" filter rejected it. It is now `SHN_ABS`.
5. **The return-probe offset argument was never typed** (`dt_pid.c`
   `dt_pid_get_types`). The type string started with `user`, which is not a D
   keyword; it is now `userland`.
6. **Conditional `jcc rel32` tail calls were never recognised as returns**
   (`i386/dt_isadep.c` `DT_ISJ32`). The macro tested a little-endian 16-bit
   load against `0x0f80`, which can never match. It now tests the two opcode
   bytes. Regression: `ht_rets` offset 17.
7. **Scoped multi-word base types and module names containing `-`** did not
   parse (fixed by the frontend agent in `dt_lex.l`, after this suite found
   them). The pid checks were flipped and pass for real processes, including
   one named `pid-types`.
8. **Coverage-tree libproc lacked CTF support.** It was built with FreeBSD's
   default `MK_CTF=no`, unlike the installed library. It is now rebuilt with
   `WITH_CTF=yes`, so `Pname_to_ctf` works as in production. This was a test
   configuration difference, not a product defect.

The suite also asserts:

- the refusal diagnostics for bad name, offset, lookup, `-` misuse, failed
  MAKEPROBE of each type, bad pid, and grab failure (including a USDT-only
  provider for a nonexistent process)
- `:LM0`a.out`, basename module globs, the stripped-binary `.dynsym`
  fallback, and `_init`/`_fini`/size-0/non-function filtering
- `*` across all functions against `llvm-readelf .symtab`
- hex-name offset globs (`1*`, `?`)
- the epilogue-only scan for functions with undecodable bytes
- that the int3 byte is resolved through GETINSTR when fasttrap answers, and
  that the function is treated conservatively when it does not
- missing fasttrap (ENOENT/EACCES)
- USDT: refused helper device, refused DOF, and registration once per process
- CTF types for entry and return probes, offset probes (none), unknown
  functions, functions without CTF, and targets without CTF

Single-suite coverage: `dt_pid.c` 84.2% lines (from 35.4%); `dt_isadep.c`
89.8% lines, 83.6% branches.

**Recorded limitation, inherited from FreeBSD.** FreeBSD's librtld_db never
reports `RD_DLACTIVITY`: `rd_event_getmsg` always answers `RD_POSTINIT`, and
`dt_proc_attach` watches only POSTINIT. So pid and USDT probes are not
created in libraries loaded with dlopen() after compilation, and
`dt_pid_create_probes_module` (about 45 lines) is unreachable. The late-load
check asserts this explicitly, and states what to expect if support is added.
Implementing it needs new process-control work in librtld_db and dt_proc:
user decision.

Also unreachable on FreeBSD:

- branches for object names containing `/`, because libproc passes basenames
- the `LM` link-map parsing in `dt_pid_get_types` (illumos only)
- `D_PROC_BADPROV`, because an all-digit provider parses as a probe ID
- allocation and `Pread` failures (defensive)

### x86 instruction-length decoder (coordinator, 2026-10-21)

New suite `instr-size-exhaustive.py` (argument: library). It generates
encodings instead of sampling real binaries:

- every opcode of the one-byte, 0F, 0F38 and 0F3A maps, under 11 legacy/REX
  prefix sets, with seven ModRM/SIB/displacement shapes for every reg field
- all 256 ModRM bytes (plus SIB+disp32) for x87 and group opcodes, under four
  prefix sets
- 3DNow!
- VEX (C5/C4) and EVEX (62) across maps, W, L, pp and vvvv, with the inverted
  R/X/B/R' bits both set and clear

Each candidate is sized in 64- and 32-bit mode by `dtrace_instr_size_isa()`
and by libLLVM 19's `LLVMDisasmInstruction`. Classification:

- A length difference fails the suite: a pid/fasttrap probe would land
  mid-instruction.
- A libdtrace refusal is conservative and counted.
- Encodings LLVM rejects, or decodes as a bare prefix (a prefix that cannot
  apply, which the CPU rejects with #UD), are counted as invalid and not
  judged; `instr_size.c` documents that invalid instructions are not flagged.
- Operand-size-prefixed near branches are counted separately and not judged:
  Intel ignores 66 there in 64-bit mode, AMD honours it, LLVM is
  inconsistent, and compilers never emit them.

Two decoder bugs fixed in `sys/cddl/dev/dtrace/x86/dis_tables.c`. The kernel
compiles this file too, and the kernel agent has been told.

1. **AMD SSE4a EXTRQ/INSERTQ** (`66`/`F2 0F 78`, register form, two imm8) were
   sized as VMREAD, two bytes short. The SIMD prefix-table rewrite runs only
   for SIMD addressing modes, and VMREAD/VMWRITE's are not, so the SSE4a
   entries were unreachable. They are now routed explicitly. Memory forms,
   where EXTRQ/INSERTQ are undefined, decode as VMREAD with no immediates, as
   LLVM does. The two macros this made unused are removed.
2. **EVEX with no implied prefix used the 0F table for every map.** Maps
   0F38/0F3A (and reserved map 0) decoded as unrelated 0F instructions, for
   example VREDUCEPH/SH one byte short, without its imm8. These are now
   refused.

Before the fixes, 2,942 length differences remained after classification
(`isz-exh-2-20261021`); the pass ran against the fixed library
(`isz-exh-6-20261021`). After them, none remain:

- 287,254 encodings agree in 64-bit mode and 452,113 in 32-bit mode.
- The real-binary differential still agrees on all 269,891 instructions it
  checks.
- `dis_tables.c` coverage rose from 46.9% to 96.3% lines and 93.3% branches.
  The rest is unreachable from libdtrace: errors for truncated input
  (`dtrace_dis_get_byte` never fails) and SIZE16 CPU mode.

### USDT linking, dtrace -G (coordinator, 2026-10-21)

New suite `usdt-link.py` (argument: world), with 78 checks
(`usdt-link-4-20261021`). Sources: `usdt-link.d`, `usdt-link-a.c`,
`usdt-link-b.cc`, `usdt-link-main.c` and `usdt-link-bad.c`. None of its
oracles come from libdtrace:

- **Call sites.** Taken from relocations in pristine copies of the objects;
  the coverage includes a static function, a tail call, is-enabled probes,
  C++ and a `__` probe name.
- **Rewritten bytes.** LLVM disassembles each rewritten call site, which must
  be no-ops, `ret` first for a tail call, or `xorq %rax,%rax` for is-enabled
  probes. No live relocation may bind `__dtrace*` symbols.
- **DOF.** Parsed from the `sys/dtrace.h` layouts. Providers, probes and native
  argument types must match `usdt-link.d`. Each probe's function relocation
  and offsets must match the call sites; is-enabled offsets are +3 on LP64
  and +2 on ILP32.
- **Linking.** The executable links with no unresolved probe symbols.
  Re-linking already rewritten objects gives the same DOF and leaves the
  objects unchanged.
- **Lazyload.** Produces `___SUNW_dof` without drti and the same DOF.
- **32-bit.** `-32` with `-m32` objects produces ELF32 output and an ILP32 DOF.
  It uses lazyload because no 32-bit `drti.o` exists without lib32.
- **Refusals.** No such probe, no such provider, probe name too long, a call
  through the GOT (`-fno-plt`), a 64-bit object in a `-32` link, a foreign
  machine, a declared provider without call sites, and archive input.

Defect fixed in `dt_link.c`: the archive diagnostic ("archives are not
permitted; use the contents of the archive instead") could never appear.
elftoolchain's `elf_begin(ELF_C_RDWR)` refuses archives first, so users saw
"failed to process …: Invalid argument". The `ar(5)` magic is now checked
before `elf_begin()`, and the unreachable `ELF_K_AR` case is removed. Also
fixed earlier: the missing `.note.GNU-stack`, which broke every USDT
executable link.

`dt_link.c` coverage with this suite alone went from 48.6% to 76.7% lines and
55.0% branches.

Unreachable on amd64:

- `mixed ELF machine types`, because each ELF class accepts exactly one
  machine
- the non-x86 `dt_modtext` variants, which are not compiled

### Daemon agent results, verified (2026-10-21)

Source: `COVERAGE-daemon.5BSD.md`. The coordinator checked the evidence
directory `cov-daemon-final2-20261021/summary.json`: all six drivers exited
0, with 234 profiles merged cleanly.

| Component | Lines | Branches | Functions |
|---|---|---|---|
| dtraced | 24,980/30,352 (82.30%) | 14,718/21,910 (67.17%) | 776/795 (97.61%) |
| dtracedctl | 243/258 (94.19%) | 126/132 (95.45%) | 7/7 |

Six defects were fixed with regression tests:

1. The wire header rejected binary 128-byte program identities. dtraced-client
   was rerun after the fix and passes (`dtraced-client-recheck-20261021`).
2. The getopt `char` loop never terminated on unsigned-char ABIs.
3. printf format mismatches broke the `DTRACED_DEBUG` build.
4. Inherited ignored SIGINT/SIGTERM hung shutdown.
5. The INFO reply was stranded (5 of 10 runs before the fix, 0 of 20 after).
6. A replayed ELF frame could precede the registration status byte (10 of 90
   cycles before the fix, 0 of 90 after; the regression is statistical).

Most of the line and branch gap is the continuity/handoff code in
`dtraced_directory.cc`, which is 63% of the denominator and needs
multi-incarnation peers.

Open user decisions:

- whether handoff code counts toward the target
- whether to remove the dead code: 10 `dtraced_connection.cc` functions,
  `waitpid_timeout`, `job::ident`, and the empty `dtraced_id.cc`
- whether to keep dtracedctl's duplicate defensive checks
- the NAK after a truncated body
- unlink retry versus cleanup ordering

### Late dlopen() pid/USDT probes (user-approved item 3, 2026-10-21)

Probes in libraries loaded after compilation are now created. FreeBSD never
supported this.

Design:

- **librtld_db** (`rtld_db.c`, `rtld_db.h`).
  - `rd_event_getmsg()` now reports the event at the stopped PC, whether or
    not the caller has rewound it past the breakpoint: `_r_debug_postinit`
    gives `RD_POSTINIT`, and `r_debug_state` gives `RD_DLACTIVITY` with the
    real `r_debug.r_state` (`RT_ADD`/`RT_DELETE`/`RT_CONSISTENT`).
  - Before, it always answered `POSTINIT`/`CONSISTENT`.
  - rtld does not export `r_debug`, so the agent finds it the way debuggers
    do: through the main executable's `DT_DEBUG` entry. The dynamic section is
    located from `AT_PHDR`/`AT_PHNUM`, with the `PT_PHDR` bias for PIE. ILP32
    targets are handled.
  - `rd_agent_t` gained `rda_rdebug_addr` at its end. Consumers never
    allocate the struct.
- **dt_proc.c.** `dt_proc_attach()` also watches `RD_DLACTIVITY`.
  - The existing `dt_proc_rdevent()` runs `dt_pid_create_probes_module()` on
    `RD_CONSISTENT`.
  - Repeated hits work through the existing `Pxecbkpt` re-arm. `POSTINIT`,
    main, exit and grab/release behaviour are unchanged; the lifecycle checks
    pass.
- **USDT de-duplication** (`dt_proc.h`, `dt_pid.c`). Each process keeps the
  DOF it has registered (`dpr_dofs`, keyed by DOF address and object base),
  so every rtld event no longer re-registers every object. Entries for
  unmapped objects are pruned on each event, so a library reloaded after
  `dlclose()` is registered again. The list is reset on exec and freed on
  release.
- **libproc fix found on the way** (`proc_rtld.c`, `proc_create.c`,
  `_libproc.h`). `proc_updatesyms()` zeroed the mapping array without
  releasing the file records, leaking each object's descriptor and ELF
  handle. It also left `nmappings` counting the stale entries, so the array
  grew on every update. It now uses the release loop shared with
  `proc_free()` (`proc_clearmappings`). With rtld events now arriving, this
  mattered: one load/unload cycle run leaked 39 descriptors with the pre-fix
  libproc and none after (`pid-late-fdleak-before-after-20261021.log`; the
  pre-fix copy was built in `libproc-before-*-20261021`).

Tests (`pid-placement.py`, 101 checks, `pid-late-2-20261021`). The former
limitation check is now the real expectation, run both plain and with a
dlclose/re-dlopen cycle (`pid-late-target`, new `pid-late-none.c`). For each:

- every load base the target reports through dladdr matches llvm-nm
- no probes or DOF exist before the load
- one `ht_late` entry request per load, for the late process only (a program
  for another process gets none)
- the library DOF is registered once per load, at its load base
- a library with no probes of interest creates nothing
- the re-evaluation ENABLE is sent correctly at least once per load
- the target exits 0
- the harness's descriptor count is unchanged after release

Fail-before: in `pid-ext-10-20261021` the old limitation check passed, so no
late probes or DOF were created.

Coverage (this suite): `dt_pid.c` 89.4% lines, 75.2% branches, all
functions, including `dt_pid_create_probes_module`; `dt_proc.c` 77.3% lines;
librtld_db 77.2% lines; libproc 70.8% lines.

`lib/librtld_db` has no tests directory, so pid-placement drives it.
`build-bsd.c` needs no change: no build inputs, staging, signing or
publication changed.

### Consumer group results, verified (2026-10-21)

Details: `COVERAGE-lib-consumer.5BSD.md`. Evidence:
`lib-consumer-20261021/final3`, measured under the build lock (library
sha256 ca4dbf2e…6996). The coordinator checked that every suite log in final3
ends in PASS; result files with zero "passed" counts only use a different
result schema.

Lines / branches, from verify2 to now:

| File | Lines | Branches |
|---|---|---|
| dt_consume.c | 74.0 → 98.9% | 62.9 → 96.0% |
| dt_printf.c | 60.6 → 99.5% | 53.3 → 97.9% |
| dt_print.c | 53.5 → 97.7% | 37.9 → 97.8% |
| dt_aggregate.c | 64.4 → 98.0% | 50.7 → 91.9% |
| dt_subr.c | 64.9 → 99.1% | 53.4 → 98.6% |
| dt_program.c | 67.5 → 98.6% | 55.4 → 96.3% |
| dt_handle.c | 67.7 → 100% | 39.6 → 95.3% |
| dt_hashmap.c | 56.2 → 100% | 41.3 → 98.9% |
| dt_analysis.c | 57.7 → 100% | 63.5 → 99.1% |
| dt_dof.c | 79.2 → 99.1% | 62.2 → 95.8% |
| dt_map.c | 88.5 → 99.3% | 73.7 → 87.1% |
| dt_buf.c | 83.5 → 100% | 65.0 → 100% |
| dt_work.c | 81.9 → 100% | 68.5 → 98.3% |
| dt_sugar.c | 83.3 → 86.5% | 72.0 → 77.7% |

Every function in these files is covered. Each remaining branch gap is listed
with its reason: assert false sides, device-only usym/umod paths, kernel-data
nrecs checks, structured-output errors that cannot fail, and dt_sugar visitor
cases.

**Defects.** About 40 were fixed, among them:

- dt_trunc returned the wrong error code
- agghist with avg/stddev aborted the process
- dtrace_sprintf freed its buffer twice
- %T used the ISO week-based year
- print() overflowed the stack on 128-bit integers
- clear() wiped the lquantize/llquantize parameter word (SIGFPE)
- the hash map compared pointer keys by content
- dof_construct_kvartab called errx() on malloc failure
- dtrace_addr2str truncated module-only strings
- dt_attr_str read one past its table
- the version parser overflowed
- structured output printed "(null)" and reported success on allocation
  failure

Most fixes have a regression case that failed before the fix; the exceptions
are listed in the group record.

**Verifier, user decision 7.** `dt_prog_bottom_rtype_ok()` now restricts the
return type of BOTTOM-typed base DIFOs. Of 22 new mutants, 11 were wrongly
accepted before the fix; all 22 get the right verdict after it.

**New suites, added to coverage-library-refresh.py:** consume-records,
printf-conversions, printf-faults, aggregate-walk, program-properties,
subr-handle, subr-faults. The same edit also added frontend-parser-scoped,
frontend-runtime-open, instr-size-exhaustive and usdt-link.

**Open and routed:**

- dtrace -E host round trip, two causes:
  - TYPECAST left in a received program, apparently an unlinked ELF being
    routed (daemon agent).
  - `dtdt_ckind` holding a CTF type id instead of a kind (typing agent).
- Joined printa checks every %@ against the first aggregation (frontend
  agent).
- dt_error.c message edge cases (typing agent).
- libctf reports every enum as int-sized, and libxo emits raw control
  characters in JSON strings. These are outside this workstream.
- Duplicate verifier checks at dt_program.c 1037 and 1579-1628 remain as
  waivers: the permission classifier refused their deletion.

### Kernel/guest results, verified (2026-10-21)

Details: `COVERAGE-kernel.5BSD.md`. Driver: `tests/coverage-kernel.py`, five
suites. Evidence: `cov-kernel-final-20261021` and
`cov-kernel-final-sanitize-20261021`. Coordinator check: all suites exit 0
both with coverage and under ASan/UBSan, and `sources_unchanged` is true.

Coverage of changed-vs-HEAD lines:

| File | Changed lines |
|---|---|
| dttransport.c | 100% |
| virtio_dtrace.c | 98.5% |
| hypertrace.c | 96.8% |
| hypertrace_map.c | 100% |
| vmm.c hooks | 100% |
| **dtrace.c** | **79.5%** (whole file 65.4%) |

Ten defects were fixed with pre-fix evidence. Among them:

- The host panicked (INVARIANTS) on a binary operation between two
  guest-tagged values.
- **Unbounded VM ids from DOF and PROBEMATCH indexed the 1024-entry per-VM
  tables, giving out-of-bounds kernel reads or a host panic by any opener of
  /dev/dtrace.** These now return EINVAL.
- The immstack cache tested its CAS result backwards.
- virtio TX control buffers leaked at detach.
- An uninitialized frame offset was read.

Next round (in progress):

- reach dtrace.c's ~490 reachable unexercised lines
- classify uncalled functions (unwired feature versus superseded leftover)
  and remove the leftovers
- fix FreeBSD's rw/sx `*_held` subroutines, which dereference once more than
  they should, and the bcopy/copyinto fault address
- gate HYPERCALL_TEST, which guest ring 3 can call to flood the host console
- fix the ineffective hw.vmm.hv_mode write

Behaviour questions for the user:

- Guest-tagged scalar stores give ILLOP.
- ENABLE returns ENOMEM instead of truncating long names.
- dist close runs on every consumer close.
- hypertrace_probe trusts the VMM epoch, and dtrace_open uses si_cred.

Live-only: real VMX/SVM exits, EPT walks, guest entry, virtio against a real
daemon, fbt frames, the fault handler, SMP, arm64/riscv builds, and KMSAN.

### Front-end group results, verified (2026-10-21)

Details: `COVERAGE-lib-frontend.5BSD.md`. The run used a locked snapshot of
the instrumented tree (`lib-frontend-20261021/snap-final`, libdtrace
0ecc99a7…). The coordinator checked that all 38 suite runs exited 0.

97% on both lines and branches: dt_string, dt_list, dt_inttab, dt_strtab,
dt_options.

| File | Lines | Branches |
|---|---|---|
| dt_options | 99.4% | 99.2% |
| dt_open | 98.2% | 95.8% |
| dt_provider | 100% | 92.2% |
| dt_module | 97.9% | 92.8% |
| dt_as | 97.5% | 90.3% |
| dt_cc | 96.5% | 92.3% |
| dt_cg | 95.6% | 84.6% |
| dt_parser | 92.7% | 85.7% |
| dt_ident | 91.9% | 70.6% |
| dt_lex.c | 79.6% | 71.2% |

dt_lex.c includes about 350 lines of generated flex machinery that libdtrace
never enters.

**Defects.** 42 fixed, each with failing-before evidence. Among them:

- constant folding disagreed with C and with run-time casts
- dt_cg: signedness casts, mixed-sign comparisons and division, and register
  leaks
- dt_probe_lookup could return another provider's probe
- dt_options: three DOF option-import faults, one of them an endless loop
- dt_string kept the backslash in `\'` and `\?`
- the parser accepted end of input inside a comment
- silent miscompiles under allocation failure
- the joined printa type check (every `%@` checked against the first
  aggregation)
- the scoped type names fixed earlier
- fterr is now ENODEV

**Coordinator fix in dt_proc.c**, which the frontend agent reported:

- `dt_proc_init`'s error path skipped entry 0, and ran out of bounds when the
  first strdup failed.
- `dt_proc_fini` dereferenced a NULL environment after a partial init.

The open fault sweep previously had to skip `dt_proc_init`. It now injects
every allocation (0 skipped) and passes 6,050 checks
(`frontend-open-envfix-20261021`).

All 16 front-end suites are registered in coverage-library-refresh.py.

Next round (in progress): the reachable untested items, classifying
dt_node_is_builtin, dnwarn and dt_ident_builtin, and removing provably
redundant checks.

Routed elsewhere:

- The DIF emulator's CMP sets cc_v = 0, so signed compares are wrong on
  overflow (kernel agent).
- dt_idhash_populate longjmps through a NULL pcb (typing agent, as part of
  the error-return rework).

Outside this workstream: libctf adds no tail padding to D structs, and
libelf/libproc/librtld_db assert or abort on allocation failure.

### bhyve / VM tooling results, verified (2026-10-21)

Details: `COVERAGE-bhyve.5BSD.md`. Driver: `tests/coverage-bhyve.py`.
Evidence: run `cov-bhyve-run-b6-final`, report `cov-bhyve-report-b6-final`.
Measured on amd64 in the production configuration (BHYVE_SNAPSHOT on). The
coordinator checked that all 98 suites passed.

| Component | Lines | Branches |
|---|---|---|
| bhyvectl | 97.6% | 94.7% |
| libvmmapi | 99.1% | 94.0% |
| bhyve control code, HyperTrace/migration paths | 97.2% | 87.5% |
| migration | 96.05% (97.75% with slices credited) | 89.4% |
| hypertrace.c + pci_virtio_dtrace.c | 88.5% | 73.0% |
| snapshot | 84.1% | 70.8% |

The branch target is not yet met for any component.

**Defects fixed**, each with a regression test. /usr/src has bugs 2–4 as
well:

1. bhyvectl read past the end of the buffer when printing an unknown CPU
   vendor.
2. vm_setup_freebsd_registers_i386 ignored an error from setting the CS
   descriptor.
3. show_memmap printed a NUL byte.
4. The apic_access_addr and virtual_apic_addr options printed nothing.

Two capsicum test variants (bhyve-sockets.c, bhyve-connect.c) now run in the
production configuration.

**Remaining gaps:**

- Continuity/handoff paths: `handoff_enabled` is hard-coded false in
  snapshot.c, in line with the fresh-session contract. The user decides
  whether this code stays.
- Paths that need a running guest.
- arm64/riscv code, which was not built (QEMU, pending the user's approval).

**Next round (in progress):**

- fix bhyvectl_md_main's exit status, the unchecked malloc in gdb.c, the leaked
  devmem slot, and the stale print_progress character
- cover the branch gaps
- classify the uncalled functions

### Typing group results and the error-return rework (2026-10-21)

Details: `COVERAGE-lib-typing.5BSD.md`. Evidence:
`lib-typing-20261021/cov-final6`. Library sha256 8bb34f2e…5394. All 14
typing harness runs pass (620 cases), as do elf-coverage-matrix,
linker-corpus, linker-offline, ctf-linker-bounds, program-verify-mutation and
coverage-cli (477/477).

| File | Lines | Branches |
|---|---|---|
| dt_typing.cc | 99.25% | 98.27% |
| dt_typing_subr.cc | 99.13% | 98.80% |
| dt_dfg.cc | 99.67% | 98.91% |
| dt_elf.cc | 98.90% | 98.44% |
| dt_typing_var.cc | 100% | 96.55% |
| dt_typing_reg.cc | 95.69% | 97.06% |
| dt_hypertrace_linker.cc | 98.09% | 94.56% |
| dt_typing_helpers.cc | 96.99% | 93.33% |
| dt_typefile.cc | 95.69% | 95.21% |

**libdtrace no longer exits the process on program errors** (user decision 1).

- `dt_set_progerr()` records the error and returns.
- All ~106 callers propagate it, and `hypertrace_link` returns
  E_HYPERTRACE_TYPING or E_HYPERTRACE_SYS.
- Guest error forwarding returns each failure with its reason, and always
  unlinks the temporary file, which also fixes the
  /tmp/ddtrace-set-prog-err.* leak.
- Also converted: the bad-label errx in `dt_basic_block.cc` (now
  `checkDIFO`), the kldstat errx in `dt_typefile.cc`, and the
  `dt_idhash_populate` longjmp through a NULL pcb (which was a SIGSEGV).
- dtrace(1) output and exit status are unchanged.
- Regressions: an in-process caller continues after the error, 200 repeated
  failures leak nothing, and every guest forwarding failure point is
  exercised.

**Also fixed:**

- `dtdt_ckind` held a CTF type id instead of a kind. The x = 1 program now
  round-trips through link, serialize, parse and verify
  (`typing-roundtrip`).
- process-global linker state persisted across handles
- struct-by-value copies into `this->` and `self->`
- the size of a dereferenced userland struct
- `dtdo_types` was never freed
- a second anonymous struct member resolved to the first
- seven bugs in dt_elf.cc
- the dt_error.c message edge cases

**Next round (in progress), correctness bugs to fix:**

- The linker's sll/sra removal before a typecast drops sign extension, so
  `trace((char)arg0 + 1)` gives the wrong result.
- **vprog makes one hypercall per action, so each host action runs N times per
  guest firing.**
- checkStack returns an uninitialized stack, computeCFG adds no fall-through
  edges, and getVariableInfo decodes stores only.
- `rand()` and `arg*` types disagree with the ident table.
- Dead functions are being classified per the user's rule.

Open design question: the kind and by-reference size of a BOTTOM result are
still trusted from the guest (9 known-gap mutants).

Routed to the front-end agent: the huregs[0] crash in dt_cg, a 2.9 KB leak per
statement, and the errx in dt_resolver.c.

New suites added to coverage-library-refresh.py: typing-inference and
elf-coverage-matrix.

### Kernel round 2, verified (2026-10-21)

Evidence: `cov-kernel-round2-20261021` and its sanitize counterpart. All five
suites exit 0 both with coverage and under ASan/UBSan, and
`sources_unchanged` is true.

dtrace.c changed lines: 3702/4008 (92.4%) without waivers, and 98.83% with the
262 waived lines excluded. Waivers are listed in `tests/kcov/waivers.txt` by
function, guard regex and reason, and the driver reports both views. Waived
classes: vm-tag, privilege, guest-args, dominated, invariant.

**Removed** (superseded or never used):

- `dtrace_vmloadmem`, `dtrace_strcmp`, `dtrace_epid2size`
- `virt_state` with its callout and tick (a planned kernel-owned guest session
  that nothing ever set)
- 12 helpers in `dtrace_vm_subr.c` and 2 in `dtrace_db.c`

`dtrace_addrxlate` now sits under `#ifdef illumos`.

**Fixed:**

- the rw/sx `*_held` subroutines dereferenced one level too many (also
  upstream)
- `bcopy`/`copyinto` reported the wrong fault address
- DIF CMP left the signed-overflow flag at 0
- a guest NULL string in a comparison now compares as the empty string
- zero-length guest accesses no longer fault
- HYPERCALL_TEST is now ring 0, with its printf rate-limited; guest-visible
  change: a ring-3 call returns ERROR
- the `hw.vmm.hv_mode` tunable now rejects invalid values
- a race in which a retransmitted SESSION_STOP stopped the new session after
  COMMIT (regression `stop-activation-race`)

**Round 3 (in progress):**

- `filterfind` is kept and commented as a future feature (the user's rule for
  unwired features)
- dominated checks are removed in 5BSD-written code and kept, as
  `dominated-upstream` waivers, in FreeBSD-origin code
- the 44 reachable lines are being covered
- symbol-table faults in the ISA files are marked live-only

### Front-end rounds 2–3, verified (2026-10-21)

Details: `COVERAGE-lib-frontend.5BSD.md`. Run: final-run2 on a locked
snapshot (library 26dd22ef). 38 of 39 suites passed.

The failure is ctf-linker-bounds, which asserts in relocateDFGNode. It passed
on 0ecc99a7. It has been routed to the typing agent, whose linker changes fall
in between.

97% on both lines and branches: dt_string, dt_list, dt_inttab, dt_strtab,
dt_options, dt_open (98.2/98.2), dt_module (99.3/98.7), and the dt_grammar.y
rules (99.2%).

Below that:

| File | Lines | Branches |
|---|---|---|
| dt_cc | 97.4% | 94.1% |
| dt_ident | 96.3% | 93.2% |
| dt_cg | 96.5% | 87.5% |
| dt_parser | 93.6% | 87.3% |
| dt_decl | 95.7% | 92.2% |
| dt_xlator | 95.6% | 92.2% |

The hand-written dt_lex.l rules are at 97.5% lines and 84.9% branches.
Generated flex and yacc code is not counted, per the earlier decision.

**Fixed in round 3:**

- `huregs[0]`/`hargs[0]` crashed the compiler; they are now refused with a
  diagnostic. Making them usable needs a new DIF encoding (a possible future
  decision).
- a 2.9 KB leak per statement (`pcb_symtab`)
- errx in dt_resolver.c, which also had an 8-byte sysctl overrun
- a slot mismatch for dt_module's process CTF (NULL dereference)
- `dm_pid` cleared after a failed load
- the stability rule was skipped for globs over D-declared probes
- about 25 provably dominated checks removed

**Dead code:**

- `dt_ident_builtin` and `dnwarn` were superseded leftovers and are removed.
  The coordinator removed `dnwarn` (dt_parser.c and dt_parser.h); upstream
  never called it either.
- `dt_node_is_builtin` is an unwired HyperTrace audit feature. It is kept and
  commented as a future feature, and the comment notes that its condition is
  always true and must be fixed against the specification before use.

Routed: dt_elf.cc's `applyResolverFilter` would silently drop a statement on
DT_RESOLVE_ERROR (typing agent).

New suite: frontend-parser-kernel, registered.

### Evidence cleanup (2026-10-21)

At the user's request, superseded evidence under
/usr/obj/5BSD-hypertrace-validation was deleted: 5,448 entries, about 413 GB.
Evidence directories cited above that are no longer present were removed by
this cleanup.

Kept:

- the shared instrumented build (`coverage-compiler-20261020`) and its compiler
  wrapper
- the build lock and the agent brief
- `keep-baseline/prior-coverage.json`, the file inventory for
  coverage-library-refresh.py
- the working directories of agents still running (lib-typing-*, cov-daemon-*,
  cov-bhyve-*, cov-kernel-*)

The final whole-library measurement will produce fresh evidence.

### Kernel round 3, verified (2026-10-21)

Evidence: `cov-kernel-round3-20261021` and its sanitize counterpart. All five
suites exit 0, `sources_unchanged` is true, and no waiver is stale.
dtrace_hypertrace ran 127,104 checks.

Changed lines:

| File | Covered | Waived |
|---|---|---|
| dtrace.c | 3750/3973 (all non-waived lines) | 223 |
| dtrace_isa.c | 119/119 | 14 |
| dtrace_db.c | 130/130 | 12 |
| dtrace_immstack.c | 57/57 | 12 |

Waiver classes: future-feature (filterfind), dominated-upstream, live-only,
infeasible, privilege, vm-tag, guest-args, invariant.

**Branch target not yet met:** dtrace.c changed-line branches are 1979/2526
(78%). This is round 4.

**Fixed:**

- `dtrace_dtr()` and `dtrace_unload()` never freed the anonymous state (21 KB
  per anonymous boot; also upstream).
- An infinite loop in probe context in the dtrace_isa.c empty-frame fill.
- Dominated checks in 5BSD code replaced by ASSERTs.

Newly covered: the helper provider, anonymous tracing, and the
state_immstack allocation sweep.

**VM_FREE_MEMSEG is not applied.** The permission system refused the edit to
`sys/dev/vmm` and is awaiting the user's explicit approval. The proposed
design is in COVERAGE-kernel.5BSD.md.

### Consumer round 2, verified (2026-10-21)

Evidence: `lib-consumer-20261021/final4`, measured under the build lock
(library f3953208…14a4). All 26 suites pass.

Branches: dt_aggregate 93.9%, dt_consume 96.3%, dt_program 96.9%, dt_dof
96.3%, dt_handle 95.3%, dt_map 88.3%, dt_sugar 77.7%. All other files are at
97% or above, and every function is covered.

Every outcome still missing is either the false side of an assert or has a
written proof that it cannot be reached:

- dt_sugar: 22 visitor outcomes. Sugar runs only on freshly parsed clauses,
  which never contain those node kinds. The code is kept for parity with
  upstream.
- dt_map: lookups that cannot fail once the formats are loaded.
- dt_consume: the nrecs==0 checks, now dead because dt_map rejects
  zero-record descriptions; kept as defence against bad kernel input.
- dt_aggregate: reverse-sort comparison sides that the internal sort never
  reaches.
- dt_program: the duplicate verifier checks, which the permission classifier
  refused to remove, plus proven-unreachable outcomes.

**Fixed:**

- An aggregation description with only a value record crashed the consumer
  (assert); it is now refused with EDT_BADAGG.
- A malformed description in a joined walk's zero-fill hit `assert(0)`; it is
  now refused.
- dt_aggid_add accepted a description with zero records, and
  dt_aggregate_snap then read before the record array; now refused.
- dt_work.c: an impossible ECANCELED arm was removed.

The device-only usym/umod/mod key normalization is now covered without the
device: dtrace_fdopen on an ordinary file with an ioctl interposer, plus a
read-only libproc grab of its own process, checked against dladdr,
kinfo_getvmmap and kldstat.

The vprog rewrite and the new verifier rules are re-verified: program-properties
has 122 cases, and all 22 BOTTOM mutants get the right verdict.

### Typing round 3, verified (2026-10-21)

Evidence: `lib-typing-20261021/cov-r5`, library f3953208…14a4. Every suite
exits 0: typing-inference (646 cases), elf-coverage-matrix, linker-corpus,
linker-offline, ctf-linker-bounds, program-verify-mutation,
program-properties, frontend-runtime-options, and coverage-cli (477/477).

Every typing file is at 97% or above on both lines and branches, except
dt_elf_bounds.hh (85% branches). Its 3 missing outcomes are infeasible:
libelf always copies section data into aligned buffers, and every caller
passes a constant non-zero width. Waivers elsewhere: libctf failures on valid
containers, and the failing side of compiled-in asserts.

**print() lost its type across the ELF round trip** (correctness). The host
runs the guest-returned program from its ELF, which dropped print()'s type
reference (`dtsd_strdata`). The host then printed a scalar as an untyped
number and a struct as a hex dump. `createElfStrData` now stores the
reference, and the parser restores it with a bounds check. The verifier
requires the returned references to equal the host's; without that, a guest
could make the host print memory as a type of its choosing.

**BOTTOM trust gap, option 2.** By-reference results of BOTTOM-typed base
DIFOs are bounded by `-x guestrefsize` (default 64 KiB; dtrace.1 entry
requested). The 9 known-gap mutants remain: bit flips inside the allowed kinds
and under the bound.

Also fixed:

- `dt_get_class` now accepts any class of a forward-declared definition
- `checkVarDefs` treats member addresses consistently
- the LDLS symbol check wrongly rejected `&td->td_tid` against
  `&td->td_oncpu`

### Kernel round 4, verified (2026-10-21)

Evidence: `cov-kernel-round4-20261021` and its sanitize counterpart. The
dtrace_hypertrace, dtrace_vm_subr, virtio_dtrace and dttransport suites exit 0
both with coverage and under ASan/UBSan, and `sources_unchanged` is true.
dtrace_hypertrace ran 131,641 checks. The vmm suite was not rerun: it is
blocked by the permission classifier and awaits the user.

With waivers excluded, every kernel component is at 97% or above on both
lines and branches. dtrace.c changed lines are 3758/3758, and branches are
2097/2133 (98.31%); the 36 open outcomes are reachable in principle (large
limits, sharing cases, predicate-cache hits). The other files are at 100%,
except virtio_dtrace.c, which has 1643/1649 lines (6 uncovered lines from
earlier rounds) and 100% branches.

Branch waivers are in `tests/kcov/branch-waivers.txt`. Macro-expansion
outcomes are classified automatically (assert, macro-constant), and stale
entries are reported. Classes: assert, macro-constant, invariant, vm-tag,
privilege, guest-args, live-only, dominated-upstream, freebsd-constant,
infeasible.

**Fixed (upstream code):** `ASSERT(nframes > 0)` panicked an INVARIANTS kernel
on a zero STACKFRAMES, USTACKFRAMES or IMMSTACKFRAMES option, which is
consumer input. The record-size check already returns EINVAL.

**Reverted to upstream:** the agent's earlier change to the validator's LDGA
check for the guest/host array ranges.

**Added:** the end-to-end vprog check. A guest firing makes one hypercall,
and the host sees each record of a 3-action clause exactly once, in order;
a predicate with a side effect runs once per firing.

**Pending the user's permission:** compiling and testing VM_FREE_MEMSEG,
VM_GET_RUN_WITNESS and VMMCTL_VM_LIFETIME_QUERY.

### Linker widths now match the front end (2026-10-21)

The frontend agent's cross-check (frontend-codegen-link.py, 824 checks over
812 expressions) found the HyperTrace linker recording different widths from
the front end in four classes. Values were the same. Decision: the linker
must agree with the front end, which is D's source of truth; D's
no-promotion semantics stay unchanged.

The typing agent changed the linker:

- `relocateRet()` keeps the compiler's `dtdo_rtype` unless it is BOTTOM.
- Integer results follow `dt_type_promote()` ranks.
- `setx` constants take the compiler's constant type.
- Comparisons are int.
- Also fixed: the member-symbol rule rejected union members.

Result: all 812 expressions agree on width and value (`agreement.json` is
empty). typing-inference (648 cases), elf-coverage-matrix, program-properties,
the linker suites and coverage-cli (477/477) pass. Library efb4778e…1120.

Visible output change: `trace(1)` now records a 4-byte int and prints with
" %8d" instead of " %16lld". This matches stock FreeBSD dtrace, where the
front end types an int literal as int. The width-16 output was an artifact of
the linker over-widening. Four CLI expectations were updated.

Typing coverage stays at or above 97% on both lines and branches
(dt_hypertrace_linker.cc 99.30 / 97.17).

### bhyve round 5, verified (2026-10-21)

Evidence: build 18, run cr18 (98 suites pass, no source change since the
build), report crep18b.

| Component | Lines | Branches |
|---|---|---|
| libvmmapi | 99.27% | 97.12% |
| bhyvectl | 98.86% | 98.09% |
| migration | 97.66% | 92.02% |
| control-scoped | 99.40% | 90.78% |
| hypertrace (waived) | 92.26% | 77.78% |
| snapshot (waived) | 91.11% | 77.18% |

NODE_REKEY is proven continuity-only. It is built only by
`checkpoint_queue_plan`, reached only through private snapshot restore, which
only the now-refused handoff restore can trigger. Its paths are commented and
waived. fbsdrun_deletecpu coverage is now deterministic: the test
synchronizes with the vCPU threads.

Added:

- a 24-row decision table for session authorization
- snapshot fault enumeration over fresh restore (160 faults), fresh capture
  (76) and commit plus resume (66)
- libvmmapi guard-mapping and VM_FREE_MEMSEG failure cases
- control and gdb error paths

Round 6 (in progress): hypertrace and snapshot device threads and state
machines, migration and control branches.

### Front-end round 4, verified (2026-10-21)

Evidence: `lib-frontend-20261021/final-run3` on locked snapshot
`snap-final3` (library efb4778e…). All 40 runs exit 0, ctf-linker-bounds
passes again, and the strict frontend-codegen-link passes with no width
disagreements. frontend-parser-fold agrees with cc on all 1716 expressions.

97% on both lines and branches: dt_string, dt_list, dt_inttab, dt_strtab,
dt_options, dt_open, dt_module, dt_regset, and the dt_grammar.y rules.

Below that:

| File | Lines | Branches |
|---|---|---|
| dt_cc | 98.0% | 95.0% |
| dt_ident | 96.3% | 93.5% |
| dt_decl | 96.1% | 92.7% |
| dt_xlator | 95.6% | 92.2% |
| dt_parser | 94.0% | 91.1% |
| dt_cg | 96.6% | 88.9% |

The hand-written dt_lex.l rules are at 97.6% lines and 94.2% branches.

Every remaining outcome in those files is listed individually by line:col in
the per-outcome waiver files (`A/round4/*.waivers.txt`,
`B/round4-branches.txt`), mostly failure arms of internal asserts and
infeasible outcomes, each with a proof chain. Five rest only on "no program
found" and have been sent back to be settled: dt_parser.c 302, 4209 and 4378,
and dt_lex.l B820:46 and L974.

**Fixed:**

- `ptr += ptr` passed the type check, then aborted in dt_cg; it now gives
  D_OP_INCOMPAT.
- A scoped type with more than 255 blanks between its words lost a word.
- `dt_preproc` called `fclose(NULL)` when `tmpfile()` failed.

Dominated checks removed: the dn_target empty-string tests (dominated by
`dt_resolve`'s strlen check) and redundant tests in dt_cg_type_name.

Front-end follow-up (2026-10-21): the five "no program found" waivers are
resolved. Three are now reached by tests: `string-member-dot` and
`string-member-arrow` for dt_parser.c 4209, `scoped-base-formfeed` for
dt_lex.l B820 (the missing operand was '\f'), and the existing tname tests
for L974 (the old rules file was stale). Two are proven unreachable:
dt_parser.c 302 (libctf already retries with the resolved type) and 4378
(earlier arms accept every string-compatible operand). No production change.
frontend-parser-corpus passes 840 cases on library 126860a7. None of the
front-end waivers rests on "not found" any more.

### No TYPECAST reaches the kernel (2026-10-21)

**The integration bug.** Only dtrace(1) runs hypertrace_link(), which turns a
TYPECAST annotation into a nop. lockstat, plockstat and bsdinstruments watch
compile and exec through libdtrace without linking, and the kernel's DIF
validator rejects op 84. On library 126860a7, lockstat's own program sent 40
TYPECASTs to the kernel (88 with -H, 204 with -A -s 8), and plockstat's sent
34.

**The fix.** `dof_add_difo()` in dt_dof.c writes the DIF one instruction at a
time and turns each TYPECAST into DIF_INSTR_NOP. Every DOF goes through it:
program exec, anonymous and -G DOF, and the error program. The in-memory
program and its ELF keep the annotations, so guest→host linking still sees
them.

**Tests:**

- DOF built without linking has no op 84, both through `dtrace_dof_create`
  and through the exact `dtrace_program_exec` ENABLE path.
- Annotated linked programs still verify and round-trip.
- tool-dof builds lockstat and plockstat unmodified and runs their own
  program generation and exec, against a vopen vector that models their
  kernel probes: 12/12 option sets, 0 TYPECAST.

Library c8975159…05c7. typing-inference (667 cases), program-properties
(122), coverage-cli (477/477), the front-end codegen and link suites,
pid-placement and compiler-offline all pass.

Routed to the kernel agent: confirming that the real dtrace_difo_validate
accepts these DOFs, and still rejects a crafted op 84.

### libdtrace links programs before they reach the kernel (2026-10-21)

The kernel agent found that lockstat's DOF carried DIF_OP_USETX and
DIF_OP_ULOAD, placeholders only the HyperTrace linker resolves, and the
kernel refused all 8 lockstat runs. Before the fix, the lockstat DOF had 40
USETX and 20 ULOAD in a plain run, and 116 and 58 with `-A -s 8`.

**The fix.** `dtrace_dof_create()` now runs `hypertrace_link()` on any
program that still holds USETX, ULOAD or UULOAD. That covers every path to
the kernel: program exec, augment, anonymous -A DOF, -G, and the error
program. It is idempotent, so linked programs are untouched.
TYPECAST-only programs are not linked; `dof_add_difo` still turns TYPECAST
into a nop. `dtrace_program_compiled_digest()` uses a new non-linking
internal DOF builder.

**Exposed and fixed:** libdtrace's C++ was built with `-fno-exceptions`, so a
failed `new` in the linker aborted the process (261 SIGABRTs in the
fault-exec sweep). The libdtrace Makefile now builds its C++ with exceptions,
and `hypertrace_link()` catches `bad_alloc` and returns
E_HYPERTRACE_SYS/ENOMEM. fault-exec passes 289 iterations. This changes a
build input inside the library Makefile only; build-bsd is unaffected.

**Tests:**

- tool-dof requires 0 of all four placeholder opcodes in the 12 lockstat and
  plockstat DOFs: 12/12 pass, and they failed before the fix.
- An unlinked program's DOF is byte-identical in DIF, INTTAB and DIFOHDR to
  the dtrace(1) path.
- Link errors and allocation failures are returned: 225 sweeps, 0 bad.

Library 366e36ea…be70. All typing, linker, front-end, CLI (477/477),
compiler-offline and pid-placement suites pass.

**Open, routed to the typing agent:** the type checker has no XLATE/XLARG
rule, so programs using dynamic translators cannot be linked.

**Pending:** the kernel agent's rerun of case_tool_dofs through the real
validator.

### Daemon progress (2026-10-21, interim)

**Continuity/handoff split.** The disabled future feature is marked with
comment-only HT-C BEGIN/END markers; removing them reproduces the old sources
byte for byte. About 15.4k physical lines are inside the markers (~12.9k of
them in dtraced_directory.cc), and they are waived. Live code is counted,
including same-host restart recovery.

**Crafted HANDOFF input is refused without corrupting state.** Every HANDOFF
message type, 14 operations and the import/release-import frames are swept,
and the journal tree must be byte-identical after each refusal (24,252
mutated requests, 0 failures). This sweep always runs.

**Unlink retry.** The unlink retries in place, at every publication site.

**Removed:**

- the dead connection helpers, `job::ident()` and the empty dtraced_id.cc
- the redundant dtracedctl checks, the dttransport self-check, and the
  unreachable NAK

`respond`, `send_ack` and `waitpid_timeout` are kept because other owners'
tests call them.

**Fixed:**

- Host-flow routing: the base copy lost its source suffix (which killed the
  guest channel), and the host -Y linked result was dropped. Regression:
  base-program-routing.
- record_cleanup_pending left its record behind when close or fsync failed,
  so a NAKed CLEANUP was replayed and applied twice.

**Found, now being fixed (lost delivery):**

- F1: an outbound spool whose first send fails before its pending record
  exists is never resent.
- F2: a pending record whose frame write failed is never resent.
- F3: a guest upload that was ACKed but whose cohort was not yet recorded is
  delivered to nobody after restart.

**Interim coverage:** dtracedctl 99.6% lines; dtraced live (HT-C excluded)
86.6% lines and 74.7% branches. Full fault and hostile sweep chains are
running.

The host TYPECAST came from an inbound sender, not daemon misrouting. An
end-to-end CLI check has been routed to the typing agent.

### vmm additions compiled and tested (2026-10-21)

Evidence: `cov-kernel-vmm-round4-20261021` and its sanitize counterpart.
vmm_hypertrace passes (1214 checks), and `sources_unchanged` is true.
Changed-line coverage excluding waivers: vmm.c 321/321 and 179/179,
vmm_dev.c 118/118 and 76/76, vmm_dev_machdep.c 24/24 and 8/8, x86.c 6/6.

**VM_FREE_MEMSEG** (`_IOW('v', 200)`, coordinator implementation):

- success, and a double free returns ENOENT
- refusals: reserved, out-of-range segid, unallocated, sysmem, still mapped
- ENXIO on mmap before the asynchronous destruction completes, and the id
  can be allocated again afterwards
- pending frees removed from the tail, middle and head of the devmem list
- destroying VM A while VM B holds devmem does not wait
- destroying a VM with a pending free waits on the per-VM counter
- no leaked objects

**VM_GET_RUN_WITNESS** (`_IOR('v', 201)`, amd64, 40 bytes): epoch,
guest_entries, vmid and running_vcpus, read under the memseg slock.
guest_entries == 0 proves no vCPU ever entered the guest. Tested: zero for a
new VM; 2 after one hypercall exit and 4 after two; a running vCPU is
counted; VM_REINIT resets the count.

**VMMCTL_VM_LIFETIME_QUERY** (`_IOWR('V', 200)`): returns a VM's
vmid and epoch by name. Tested: matches VM_GET_IDENTITY and follows reinit;
EINVAL, ENOENT and EPERM cases, and success with PRIV_VMM_DESTROY.

**Tool DOFs** after the libdtrace link fix: none of the four link-time
opcodes appear, and all 12 (8 lockstat, 4 plockstat) are accepted by the real
dtrace_dof_slurp and dtrace_difo_validate. **lockstat can enable again.**

The ABI has been passed to the bhyve agent for the resume retry (item 4) and
INTENT-only recovery.

### Typing round 4e: XLATE/XLARG and the host round trip (2026-10-21)

**The x = 1 round trip passes end to end.**
`dtrace:::BEGIN { x = 1; } dtrace:::END { trace(x); }` runs through the CLI
host flow: the -E consumer sends its base ELF, `dtrace -Y base.elf,host`
links and publishes it, and the consumer verifies and enables it. No
dtrace.c change was needed, since process_elf_hypertrace already links before
serializing; the original rejection came from the ckind and width bugs, both
now fixed. New CLI case: host-roundtrip-global-variable (coverage-cli
478/478).

**XLATE/XLARG** are typed from the DIFO's translator table. Both opcodes give
the translated member's type, and every failure is a program error. Every DIF
opcode now has a typing rule.

Limits, recorded and not changed:

- The kernel has no XLATE/XLARG/XLTAB support, so dynamic-translation
  programs cannot run on a FreeBSD kernel. This predates HyperTrace; static
  translation is the default.
- `dtdo_xlmtab` is not serialized in the guest ELF, so a guest
  dynamic-translation program fails on the host with a clear program error.
  Carrying the table would change the guest↔host format, which is not
  worthwhile while the kernel cannot run such programs.

Library 4bd1e7c5…d622. typing-inference (700 cases), program-properties
(124), coverage-cli (478/478), and the front-end, compiler-offline and
pid-placement suites pass. Every typing file is at 97% or above (total 98.97
lines / 97.86 branches).

### bhyve round 6, verified; migration item 3 partly applied (2026-10-21)

Run cr18z: 98 suites pass on build 18.

| Component | Lines | Branches | Branches after outcome waivers |
|---|---|---|---|
| migration | 98.35% | 94.16% | 95.56% |
| control-scoped | 99.76% | 92.24% | 95.86% |
| hypertrace | 93.24% | 79.86% | — |
| snapshot | 91.11% | 77.18% | 77.69% |
| libvmmapi | 99.27% | 97.12% | — |
| bhyvectl | 98.86% | 98.09% | — |

Per-outcome waivers in coverage-bhyve.py name an exact line, column and arm
with a class reason. The report refuses to run if a waived outcome executes,
is missing, or falls inside a continuity range.

Added:

- session state-machine decision tables
- the non-rekey paths of pci_vtdtr_run
- migration contracts and protocol edges
- the adapter's errno-less sweep

Still reachable and not yet covered: about 700 arms in the hypertrace
device and hypertrace.c, about 810 in snapshot.c and checkpoint_manifest.c,
and about 100 in migration. Round 7 is in progress.

**Migration item 3 (required TLS) is partly applied in the main session**, at
the user's instruction:

- `migration_channel_policy()` in migration_channel.h: TLS is required
  unless plaintext_unix is set and the descriptor is an AF_UNIX stream socket.
- The source IPC handler enforces it.
- migration_session.h has a `plaintext_unix` field.

The destination enforcement edit was denied by the auto-mode classifier
("Auto-Mode Bypass"). The bhyverun and bhyvectl options, the manual pages and
the tests are not done, and nothing has been built. Items 2 and 4 are not
started. Awaiting the user's choice between leaving auto mode and reverting.

### bhyve migration items 2-4 and kernel round 4 (2026-10-21)

The user left auto mode and asked for items 3, 2 and 4 to be finished in the
main session. All three are now implemented in production; build cbm-v2a
passes.

- Item 3 (mutual TLS required): migration_channel_policy() in
  migration_channel.h is applied on both ends. Plaintext is accepted only
  with the explicit opt-in (IPC key plaintext_unix,
  migration_session_config.plaintext_unix, bhyve migrate.plaintext_unix,
  bhyvectl --migrate-plaintext-unix) and only on an AF_UNIX SOCK_STREAM
  socket. HyperTrace still requires TLS. Manual pages updated. New test
  migration-channel-policy.c: 10/10 pass. The cbm-tls2-run rerun left 3
  failures, all fixtures that predate the policy (retained-owner:727, and
  adapter test_success running without TLS). They were routed to the bhyve
  agent.
- Item 2 (protocol 2): MIGRATION_PROTO_VERSION and _MIN are 2, and version 1
  peers are refused. Every migration now uses the challenge-bound FMC1 COMMIT
  (destination vmid/epoch plus the DEV_STATE digest, hashed in ordinary mode
  too), a challenge-bound RELEASE, and RELEASE_ACK. The source wedges on any
  failure after retirement. A destination never discards once COMMIT may
  have been sent: retain_eligible is set unconditionally, plain
  migration_prod_dest_serve keeps its retained owner, and bhyverun blocks
  instead of exiting. Journal records stay fresh-only (step 2, a crash-safe
  journal for ordinary mode, is deferred as agreed).
- Item 4 (resolution): new IPC migrate_resolve.
  - resume requires source_retired. After an attempted resume it also needs
    the run witness to show guest_entries == 0 and running_vcpus == 0 for
    the matching vmid/epoch; otherwise it refuses with EBUSY or ESTALE.
  - discard requires acknowledge_loss.
  - Export is not offered yet: the checkpoint path assumes running vCPU
    threads, and a retained inbound guest has never started. That case is
    with the bhyve agent to characterize, not to change.
  - Each decision is logged before it acts. A retained owner is freed with
    its own recovery directory duplicate.
  - New libvmmapi wrapper: vm_get_run_witness().
  - Suite and CLI work were routed to the bhyve agent.
- Kernel agent round 4, verified against its evidence:
  - cov-kernel-vmm-round4-20261021 and its -sanitize twin: 1214 checks,
    0 failures, exit 0, sources_unchanged. The production hashes equal the
    current tree.
  - Changed-line coverage after waivers: vmm.c 321/321 lines and 179/179
    branches, vmm_dev.c 118/118 and 76/76, vmm_dev_machdep.c 24/24 and 8/8,
    x86.c 6/6.
  - Covers VM_FREE_MEMSEG, VM_GET_RUN_WITNESS and VMMCTL_VM_LIFETIME_QUERY.
  - All 12 recaptured lockstat/plockstat DOFs pass the kernel validator, and
    none contains a link-time opcode.

### Operator CLI, build-bsd check, ordinary-mode handoff journal (2026-10-21)

The user asked for the three follow-ups to be done now.

- bhyvectl --migrate-resolve=resume|discard, with the action-specific
  confirmations --migrate-source-retired and --migrate-acknowledge-loss. The
  wrong or a missing confirmation is a usage error and nothing is sent;
  success needs resolved=true with nothing retained, and a controller
  error_code is surfaced. bhyvectl.8 documents it. Build cbm-v2b passes.
  Test migration-resolve-cli.py (mrc1): PASS, 20 reply modes across both
  actions plus 9 pre-IPC refusals.
- build-bsd: build-bsd.c has no reference to bhyve, vmm or migration, and
  items 2-4 change runtime migration behaviour only (no build input,
  staging, signing, packaging or publication change). No update needed; the
  unrelated suite was not run.
- Item 2 step 2, done rather than deferred. This supersedes the earlier note
  that journal records stay fresh-only. The HMR2 record cannot carry
  ordinary migrations (its encoder requires a HyperTrace session record and
  both certificate pins), so ordinary mode gets its own append-only handoff
  journal, usr.sbin/bhyve/migration_handoff.h: 128-byte CRC32 entries, one
  file per attempt and side (h-s-/h-d-<challenge>.log), private directory
  and file, exclusive lock across read-validate-append, fsync per entry and
  of the directory on creation, a torn tail refused rather than repaired.
  Sequence rules: INTENT/STAGED first, then +1, idempotent repeat; RESOLVE
  only before RUNNING and never while a decision is pending; OUTCOME closes
  the pending decision.
  - The core now calls so_record/do_record for every migration and
    requires both ops at hello time. do_preserve remains gated by presence.
  - Production: ordinary mode journals when a recovery directory is
    configured (source canonical root, destination migrate.recovery_fd);
    without one the transition succeeds in memory only. A journal failure
    after INTENT wedges the source as in fresh mode. migrate_resolve
    journals RESOLVE (with the admitting run witness) before acting and
    OUTCOME after; a journal refusal leaves the image retained and does
    nothing. Once prod_dest_resume succeeds the guest is resolved; later
    journal errors are reported as journal_error, not treated as failure.
    An operator resume from STAGED records RELEASED first (the confirmation
    stands in for the RELEASE that never arrived).
  - bhyve.8 and bhyvectl.8 updated. Build cbm-v2c passes.
  - Tests: migration-handoff-journal.c (mhj1): 122 expectations, 0
    failures, covering layout, every validity rule, names, the sequence
    rules, torn tail, foreign and misplaced entries, symlink, hard link,
    loose file and directory modes. migration-handoff-production.py (mhp1):
    PASS; drives the real prod_source_record, prod_dest_record and
    vm_do_migrate_resolve against a scratch directory, including the
    no-directory, refused-journal, failed-resume-then-retry and witness
    cases.
  - Not done: an operator tool to print a journal; the files are fixed
    format and small. The bhyve agent registers the three new tests.

### bhyve agent findings on items 2-4; two production fixes (2026-10-21)

The bhyve agent reported (verification of its evidence pending its full run
p23): suites updated for items 2-4 and the handoff journal, all passing on
its build cb23; errno-fallback hardening applied at the listed snapshot.c,
checkpoint_manifest.c and snapshot_devmem.c sites with fb7-old failing and
fb7-new passing the errno-0 oracle; my three new tests registered; 54
migrate_resolve checks in two-process scenarios; the protocol model's
ordinary-mode losses after RELEASE are 0 against 37 in cbm-tls1-run.
Its one-copy invariant caught a test scenario that resumed without
destroying the source; the test was corrected, not the invariant.

Two findings were verified in the code and fixed in production (build
cbm-v2d passes; cbm-v2c kept as fail-before):
- A protocol-1 framed HELLO was refused by the frame decoder before any
  HELLO was read, so a v1 peer got a transport failure instead of
  REASON_VERSION. The frame layout is unchanged since v1, so the codec now
  accepts frame versions from MIGRATION_FRAME_VERSION_MIN (1); negotiation
  still refuses v1 (MIN 2); a CAPS_REJECT sent before negotiation is encoded
  in the peer's frame version (new sess->peer_version). A v2 source to a v1
  destination remains a transport failure, which only the old peer could
  change. bhyve.8 says so.
- vm_checkpoint(stop_vm=false) on a retained, never-started destination
  completed and published, and its vm_vcpu_resume() released vCPUs parked
  by the restore startup fence while the fence still reported held: a
  checkpoint would have started the guest without a migrate_resolve
  decision. vm_checkpoint now returns EBUSY, before creating any file, while
  checkpoint_restore_startup_held(); this covers --checkpoint and
  --suspend. Export of a retained guest therefore stays unsupported, now
  enforced rather than merely undocumented. bhyve.8 updated.
The agent was asked to flip its two current-behaviour assertions and keep a
case showing checkpoints work again after resolution.

### bhyve round 7 result p24, verified (2026-10-21)

Verified against evidence: cb24 built after the last production edit
(build.json newer than migration_session.c and snapshot.c); r24 104/104
suites passed; p24 log figures match the report. Both production fixes are
covered with fail-before in r23f (test_protocol1_peers; test_fenced_checkpoint,
whose r23f probe line shows the parked vCPU released).

Strict branch coverage (lines in brackets), after outcome waivers:
- hypertrace (continuity-waived): 89.79% [95.51%], up from 79.86% at round 6
- migration: 94.68% [98.20%]
- snapshot (continuity-waived): 78.31% [91.32%]
- control-scoped: 95.86% [99.76%]
- bhyvectl: 93.07% (new --migrate-resolve and plaintext code untested yet)
- libvmmapi: 96.59% (vm_get_run_witness untested yet)

Against the goal of 97% lines and branches per component, lines are close
or above in migration and control-scoped; branches are short everywhere
except control-scoped and libvmmapi, and snapshot branches are far short.
The agent continues with bhyvectl and libvmmapi, then hypertrace and
snapshot branches. Report hardening: outcome waivers are code-anchored and
the report refuses to resolve them when a waived file changed since the
build.

### bhyve round 7 hand-back p24z, verified; round 8 started (2026-10-21)

The bhyve agent handed back. Verified: r24z 104/104 passed; p24z written
after the cb24 build; its figures match the report. Final round-7 branch
coverage after outcome waivers: hypertrace 89.75% (lines 95.51%),
migration 95.94% (lines 98.65%), snapshot 78.31% (lines 91.32%),
control-scoped 95.86% (lines 99.76%), bhyvectl 97.58%, libvmmapi 97.27%.
bhyvectl and libvmmapi are at goal, with --migrate-resolve, plaintext and
vm_get_run_witness now tested (541/541 bhyvectl checks; the vmm model
answers VM_GET_RUN_WITNESS from its VM_RUN count). The other four are not.
Open arms by the agent's count: control-scoped 19, migration 127,
hypertrace ~310, snapshot ~900. The agent was resumed for round 8 in that
order, under the same rules. Its round-7 section is in
COVERAGE-bhyve.5BSD.md.

### bhyve round 8, item 1: control-scoped at goal (2026-10-21)

Verified: r25d 2/2 suites, p25d control-scoped 452/452 branches (100%)
after outcome waivers, 829/830 lines; raw 452/477. Twelve arms covered
(raw-console EPRINTLN paths in ipc.c and bhyverun.c in both console modes,
the ipc.c rights-limit failure); a harness nondeterminism in the fatal
accept case fixed. Seven new waivers in three classes, checked by
inspection of the definitions in coverage-bhyve.py: assert-invariant (five
assert false arms in gdb_write_mem and vm_loop; the arm is the abort),
libc-total (init_ipc_thread snprintf "%s/%s" with bounded arguments),
constant-condition (the always-true operand of TAILQ_FOREACH_SAFE in
remove_all_sw_breakpoints, a macro-expansion branch keyed by site line).
The agent's claim that the justifications were already in
COVERAGE-bhyve.5BSD.md was not true at verification time; it was asked to
add a Round 8 section now and keep it current.

### bhyve round 8, items 2-3 verified; vtdtr deadlock fixed (2026-10-22)

Verified against p26b (figures match) and the runs (r26b, r26d, r26e,
r25g pass; r26a's one adapter failure is the agent's load observation,
rerun clean; r25e's ops failure was interim): migration 2347/2347
branches after outcome waivers (raw 96.82%, lines 99.18%); hypertrace
2952/2966 after continuity and outcome waivers (99.53%; 97.52% with
continuity waivers only; lines 98.70%). Waiver definitions spot-checked in
coverage-bhyve.py; 44 new migration waivers, 31 of them state-invariant,
with the agent's justifications in COVERAGE-bhyve.5BSD.md Round 8.

Agent proposals decided:
- pci_vtdtr_run worker wait predicate omitted vsd_cleanup_unapplied: with a
  CLEANUP pending, a READY guest with posted descriptors made the batch loop
  run zero iterations while the worker spun holding vsd_mtx, so
  CLEANUP_APPLIED could never be received (reproduced by the agent as a hard
  deadlock). Fixed: the flag is in the predicate; CLEANUP_APPLIED already
  clears it and signals. The agent adds the case with cb24 as fail-before.
- pci_vtdtr_notify_ready's vsd_ctrlq NULL guard: provably redundant
  (allocated at init; dereferenced unconditionally by
  restored_kills_pending). Removed under the user's redundant-check rule.
- pci_vtdtr_checkpoint_replayable's loop: kept. Not a duplicate of
  checkpoint_state_valid: elf_run_advance closes a run on hasmore == 0 with
  bytes < total, and state_valid tests only run.open, so the
  bytes != total check is the real partial-upload refusal.
- migration_prod_dest_serve_impl: owner is now mandatory (every destination
  may retain), removing the dead owner == NULL arms; nv_true's NULL check
  removed. The error == 0 fail-label guards stay, waived as state-invariant.
Build cbm-v2e passes; migration-handoff-production.py still passes.
Superseded build directories cbm-v2c and cbm-v2d removed (the agent holds
its own fail-before evidence in r23f).

### The twelve parked decisions, resolved (2026-10-22)

The user asked for "the right thing for each". Status at this writing; test
results that are still running are marked pending.

1. Staged index (1,958 files, the whole HyperTrace tree): harmless. At commit
   time the index is reset (index only, no working-tree change) and each
   per-area commit stages its own files. No action now.
2. CLI temporal default and -y.
   - temporal stays on by default. The quiesced drain no longer refuses
     temporal ordering: dtrace_consume_quiesced sets dt_drain_final around
     the consume, and the temporal path in dtrace_consume() flushes the whole
     ordering queue when that flag or dt_stopped is set, since the producer
     fence guarantees no later record. The drain also now returns ECANCELED
     when a consumer callback stops it (the arm the consumer record lists at
     dt_work.c:398 was missing from the file; restored). Fixture
     consumer-quiesced-drain.c flipped and passes (cqd1); CLI case
     drain-temporal-refused renamed drain-temporal-ordered expecting
     DRAIN-REPLY result=1 (pending the CLI run).
   - -y now does what its usage text says: process_elf enables the linked
     program (dtrace_program_exec), traces, consumes to the end and exits;
     main's DMODE_EXEC skips -y commands and returns. Before, it started
     tracing without enabling anything and then fell into the -E host
     consumer path. dtrace.1 gains a -y entry. The elfrun-* CLI cases need
     new expectations (pending the CLI run).
3. migrate.recovery_image default: stays off. The handoff journal now records
   every migration regardless; the image costs disk and time and is a
   HyperTrace-managed-receiver feature. Documented as is.
4. Journal reader: bhyvectl --migrate-journal=<file> prints one line per
   entry (position, side, kind, witness, outcome, destination identity, TLS),
   validating the journal exactly as the writer does; misnamed, missing or
   torn journals are refused whole. Names no VM, opens none, bhyvectl.8
   updated, libz linked. Test migration-journal-cli.py passes (mjc1). Build
   cbm-v2g passes.
5. Guest-tagged scalar stores: keep refusing (ILLOP). The tag is what stops a
   guest value being dereferenced as a host address later; preserving tags
   through variables is a design extension, not a fix. Documented.
6. ENABLE long names: dtrace_enabling_list now reports ENAMETOOLONG (not
   ENOMEM) for a name the description cannot hold; truncation is still
   refused because it would describe another probe. Kernel harness
   expectations flipped in t_dtrace_ioctl.inc (pending the kernel run).
7. dist close: dtrace_state_t gains dts_dists_open; the state passed to
   dtdops_open (the anon state when one exists) records it, and exactly that
   state's stop or close calls dtdops_close once and clears it. Before, every
   dtrace_close called every dist for every state, opened or not, and a
   stopped state was closed twice. Note: the tree contains no dist
   implementer; this is KPI hygiene. case_dist updated (pending).
8. hypertrace_probe epoch trust and dtrace_open si_cred: keep. The VMM is
   in-kernel and the kernel agent proved the epoch invariant; si_cred is
   upstream behaviour. Documented.
9. drti.c: the LM%lu` link-map branch is unreachable on FreeBSD (lmid is a
   constant 0 there); guarded with #ifdef illumos and the FreeBSD-only lmid
   variable removed.
10. "Same-boot collector gap": the daemon child ledger's other-boot branch,
    reachable only across a reboot. Class waiver, to appear in the daemon
    agent's final record.
11. dt_prog_verify duplicates: the four first/last-action fprintf blocks after
    dt_prog_action_span_valid() re-tested exactly what span_valid() had just
    decided; removed. The line-1037 loop is NOT a duplicate (it compares the
    new DIFO's variables against every other DIFO in the context, the first
    loop compares base against new index by index); kept.
12. PF trees and signing-elf-work: untouched, the user's.
Build frontend: none of these changes build inputs, staging, signing,
packaging or publication; build-bsd.c needs no update.

Decision follow-up (2026-10-22): kernel items 6 and 7 verified. The
dtrace_hypertrace suite (kcov-dec2) runs 131,711 checks with 0 failures,
sources unchanged, after flipping the five pinned expectations: case_dist
(no close for a state that never opened the dists; dts_dists_open observed),
and the four long-name ENABLE assertions in t_dtrace_ioctl.inc and
t_dtrace_edges.inc (ENAMETOOLONG, with the injected-allocation iteration
still ENOMEM). The first rerun (kcov-dec1) failed only on those pins.

Decision follow-up (2026-10-22): consume-records failure explained. After the
shared instrumented libdtrace was rebuilt from current sources (clean build,
libdtrace-rebuild-dec3, under the build lock), consume-records' case
dt-buf-allocation-failures failed with "create failure: err 0" while every
other malloc-fault case passed. Libraries from the typing agent's snapshots
(16:32-17:57 on 10-21) pass; only the five files I changed are newer than
those snapshots, which pointed at my edits. A debugger trace settled it
instead: dt_zalloc() at dt_subr.c:793 calls calloc(), the compiler having
folded malloc()+bzero(), and the test's fault interposer covered only
malloc() and realloc(), so no fault was injected. dt_subr.c is unchanged;
this is a test gap exposed by code generation, not a library regression. Fix:
the interposer now covers calloc() as well (same counting and countdown).
The clean rebuild also confirms the library has no mixed struct layouts after
the dt_impl.h change. The earlier incremental rebuild had first gone to a
stray object tree (wrong MAKEOBJDIRPREFIX); it was removed.

CLI: cli-dec3 passed 478/478 cases; its regression gate failed only because
dtrace.c's frozen line/branch counts changed with the -y fix (3341 lines,
1761 branches; covered 3167 and 1534 both above the old floors). The table
was re-baselined with the same tolerance pattern and the review note.

Decision follow-up (2026-10-22): CLI verified. cli-dec4, on the clean
instrumented libdtrace with the re-baselined gate: 478/478 executable cases
pass and the regression gate passes. This covers -y (elfrun-exec,
elfrun-not-executed, exec-run-elf-then-compile-only, checkmodref-elf-run)
and the temporal drain (drain-temporal-ordered). The two cases that failed
once each in earlier runs (exec-impatient: two signals on one marker;
host-stop-while-receipt-retries: empty stderr) passed in every later run and
are interleaving-dependent, not changes in behaviour.

Decision follow-up (2026-10-22): consume-records verified with the calloc
interposer: lib-dec2-consume-records, 175 consumer record cases, 0 failures,
every fault sweep passing, including dt-buf-allocation-failures.
program-verify-mutation passed against the rebuilt library
(lib-dec1-program-verify-mutation: no mutated program escaped verification
outside the documented classes). All twelve parked decisions are now
implemented and verified; the final whole-library refresh will remeasure
everything on the settled sources.

### bhyve round 8, item 4 verified; four decisions (2026-10-22)

Verified against p28f (build cbm-v2g; runs r28a 99/104 with the five
failures explained: migration-receiver and gdb-migration-fence time out only
under the 16-job load and pass alone in r28b; migration-resolve-cli,
migration-resolve-cli@prod and bhyve-cov-bhyvectl-vendor were broken by my
bhyvectl.c journal-printer change and pass in r28c after the agent repaired
the drivers: -lz on the vendor link, and the resolve-cli extraction narrowed
to migration_resolve_request). Snapshot: 3654/3716 branches after
continuity and outcome waivers (98.33%; raw 83.19%, up from 77.71% at the
item's baseline), 96.11% lines, 176/177 functions, 341 outcomes waived with
comments. Other components in p28f: migration 99.87%, hypertrace 99.63%,
control-scoped 100%, libvmmapi 97.27%, bhyvectl 93.26% (the journal printer,
untested yet). The vtdtr deadlock case is in the suite with fail-before
fb8-vtdtr (pre-fix predicate copy and diff; run.log line 7 fails).

Decisions:
(a) Lines at 96.1% because the bodies of blocks behind waived arms are not
    line-waived. Approved: a collector rule line-waives such bodies, and the
    strict view fails hard if one executes.
(b) bhyvectl dropped to 93% because migration_journal_print has no suite.
    Approved: drive the migration-journal-cli.py journals through the real
    bhyvectl --migrate-journal, plus the usage and conflict refusals.
(c) A stop_vm checkpoint whose post-publication stop or destroy fails used
    to resume the source with its HyperTrace session recorded as stopped.
    Not the intended contract: the manual says the VM terminates after the
    snapshot, and resuming a source behind a durable stopped-session image
    breaks the one-copy principle. Fixed: after stop_vm && published, any
    such failure prints the error and exits BHYVE_EXIT_ERROR; failures before
    publication still resume. bhyvectl.8 --suspend documents it. Build
    cbm-v2h; the agent flips the fresh-checkpoint fault expectation with
    cbm-v2g as fail-before.
(d) Dead or redundant operands in restore: kept, waived as defensive, except
    vm_restore_device's re-validation, which is removed only if the agent
    confirms it re-checks the same in-memory bytes the preflight validated.

### Daemon progress note 2 (2026-10-22)

The daemon agent reports F1-F3 fixed with regressions (host outbound spool
record written before memorizing; pending records resent on forwarder
admission with their recorded IDs, skipping missing or revoked spools; an
ACKed upload with no cohort and no receipt left unmemorized for the next
consumer; exact-token replay so no program reaches a VM under two tokens),
plus a guest variant of F1 and withdrawal of tokens for refused
publications. Old binary: outbound PUBLISH 137/142 fault points fail,
host-ingest 108/140; fixed binary 0/107 and 0/155. Final run
cov-daemon-final5-20261021: dtracedctl 238/239 lines, 121/122 branches;
dtraced live 15,292/16,977 lines (90.07%), 9,809/12,456 branches (78.75%);
fault, callfault, hostile (30,219 mutated requests), corrupt and
handoff-refuse sweeps all 0 failures. The run's FAIL came from three harness
bugs, since fixed; reruns under way. Verified here: the summary's only
nonzero driver status is daemon-extra; the F1-F3 section exists in
COVERAGE-daemon.5BSD.md. Fail-before directories to be named in the
hand-back. The three load-only failures were a harness race that placed
CLEANUP on a READDATA channel; the daemon still accepted that layout, which
bhyve never uses. Decision: refuse it at admission as a protocol tightening,
with a regression. The daemon is not at goal; the agent continues on the
~1,690 lines and ~2,650 branches, mostly journal I/O error returns.

### bhyve round 8 complete: p29 verified (2026-10-22)

Verified: p29 on cbm-v2h. Every bhyve component at or above 97% on both
measures after waivers: snapshot 97.45% lines / 98.73% branches (341
outcomes waived; 67+11 body lines under the new rule), migration 99.18% /
99.87%, hypertrace 99.65% / 99.63%, control-scoped 99.88% / 100%, bhyvectl
98.88% / 97.59% (new suite bhyvectl-journal drives the production
--migrate-journal; 19 checks), libvmmapi 99.33% / 97.27%. r29a 104/105 with
bhyve-cov-control a load-only timeout that passes alone (r29c); r29b passes
the flipped stop_vm oracle. Fail-before for the stop_vm fix: fb10-stopvm
(snapshot.c copy with the new block removed first on the include path;
run.log 2683-2684 shows PUBLISHED-AND-RESUMED and CHECK(!published)
failed). fb9-stopvm compiled the already-fixed tree and is not evidence; the
agent said so.

Decisions closed:
(a) The body-line rule (waived_body_lines: the body of a block whose single-
    operand guard arm carries an outcome waiver; strict view dies if a body
    line executes) stays scoped to files with a continuity entry; not
    extended to migration, which is at goal without it.
(d) vm_restore_device's re-validation checks the same in-memory bytes the
    preflight validated (one ucl parse; one digest-verified MAP_SHARED kern
    mapping; nothing re-read), so it is provably redundant. The four EINVAL
    returns are now asserts naming the preflight invariant; the compat
    envelope decode stays (it computes the payload offset). Build cbm-v2i;
    the agent drops the anchored waivers and reruns.
Also from the agent: one race-only waiver executed in r29a and was removed
(covered now); a collector regex fix for giga-range branch counts.

### bhyve at goal: p30 verified, round 8 closed (2026-10-22)

Verified: p30 on cbm-v2i (built after the vm_restore_device asserts; the
build matches the tree). After waivers: snapshot 97.50% lines / 98.71%
branches (337 outcomes), migration 99.18% / 99.87%, hypertrace 99.65% /
99.60%, control-scoped 99.88% / 100%, bhyvectl 98.88% / 97.59%, libvmmapi
99.33% / 97.27%. r30a 104/105 with migration-receiver@prod a load-only
timeout that passes alone (r30b). No waived outcome or body line executed
in the strict view. The six validator-implied waivers on the removed
vm_restore_device returns are deleted and the asserts are assert-invariant;
the function is static and reached only through
vm_restore_devices_prevalidated after the preflight, so no harness change
was needed. The bhyve agent made no production edits this round; its record
is COVERAGE-bhyve.5BSD.md. Every bhyve component is at or above the 97%
goal on lines and branches. Remaining work before the whole-library refresh
and the commits: the daemon.

### Whole-library refresh, first pass: 43/48, five failures resolved (2026-10-22)

coverage-library-refresh.py on the clean shared libdtrace (keep-baseline
inventory) failed its all-pass assertion with five suites. Each was
diagnosed to a cause before anything was changed:
- consume-ingestion quiesced-temporal: expected EOPNOTSUPP from the drain
  under temporal ordering; the drain now flushes the queue (decision 2a).
  The case moved from the refusal table to a positive drain
  (quiesced-drain-temporal: the same two records in time order). Passes.
- subr-faults (16 failures): two causes. The shim hooks calloc but the
  tests arm faults by the name "malloc", and dt_zalloc's malloc()+bzero()
  is folded to calloc() by the compiler, so an armed malloc fault never
  reached a zeroed allocation; an armed "malloc" now also counts and fails
  calloc calls (arming "calloc" still selects only those). The 14
  compiled-digest mutations never applied because the test interposed the
  public dtrace_dof_create() while dtrace_program_compiled_digest() reaches
  DOF creation through the internal dt_dof_create() since the typing
  agent's link-on-create split; the hook now interposes dt_dof_create()
  (non-static, so the executable's definition is found first). Passes: 10
  groups, 305 checks.
- frontend-parser-symbols (4 cases): the const() oracle required SETX, RET
  as the last two opcodes; the front end now emits the link-time TYPECAST
  (84) after a sizeof constant to give it its D type (size_t). The oracle
  accepts the optional TYPECAST. Passes: 37 cases.
- frontend-parser-printers (sizeof round trip): a genuine printer fidelity
  gap exposed by the typing work. dt_printd printed a folded sizeof as
  0x4ul, which re-parses as unsigned long, while the original was size_t;
  the DIFO now records the type name, so the round trip differed. Fixed in
  dt_parser.c: an integer constant whose D type is not the one its literal
  form implies (int, unsigned int, long, unsigned long by size and sign) is
  printed with an explicit cast, ((size_t)0x4ul). Library rebuilt
  (libdtrace-rebuild-dec4). Passes: 27 printer checks.
- frontend-codegen-oom: the harness required a DWARF range for every listed
  function; dt_as_xlate and dt_load_libs_sort are static and inlined in
  this build (the lib-frontend snapshots had them out of line), so they
  have no range of their own. The harness now skips an inlined static with
  a note; its code is swept within its caller's range. Passes: 30 sweeps.
The refresh is rerunning on the settled sources; the CLI suite will be
rerun once more after it because the printer change affects program text.

Whole-library refresh, second pass (2026-10-22): all 48 suites passed, the
library binary hash and every source hash held through the run, and the
run stopped at the inventory guard: the new export maps 140 files against
the baseline's 145. Reviewed: one real addition,
cddl/contrib/opensolaris/lib/libdtrace/common/dt_resolver.h (the typing
agent's header, now carrying mapped code), and six incidental system
headers no longer mapped by the clean build (machine/param.h, x86/_limits.h,
sys/_align.h, sys/_endian.h, sys/elf64.h, sys/elf_common.h), none of them
library sources. The baseline inventory was refreshed from this export
(the previous one kept as keep-baseline/prior-coverage-20261021.json) and
the refresh rerun.

### Final whole-library measurement (2026-10-22): library-final-20261022

coverage-library-refresh.py on the settled sources and the clean shared
instrumented libdtrace: 50 suites, all status 0; 1,847 fresh profiles; the
library binary hash and every inventoried source hash held through the run;
merge and export logs empty. Raw figures, no waivers applied:
- /libdtrace/ paths: lines 36,545/38,113 = 95.89%, branches 18,639/20,210 =
  92.23%, functions 1,210/1,226 = 98.69%.
- whole mapped object: lines 92.71%, branches 91.86%, functions 90.10%.

How this relates to the 97% goal, stated plainly. This refresh runs the
OFFLINE library suites only and applies no waivers; it is a lower bound by
construction. The per-component figures the library agents reported
(typing total 98.97% lines / 97.86% branches; consumer, front-end and CLI
at or above 97% per file) include the live-process suites and their
documented waiver classes (generated lexer and name tables, continuity,
other-ABI and defensive arms). There is no tool that applies those recorded
waivers to a whole-library export, so the two views are not mechanically
reconciled here. The raw gap sits where that explanation predicts: dt_lex.c
(generated, 82.6% / 76.5%) and dt_names.c (generated, 14.8% / 54.4%);
dt_link.c (77.7% / 56.4%), dt_proc.c (81.0% / 63.8%), dt_pid.c (89.1% /
74.4%) and dt_dis.c (77.0% / 73.6%), which the live-process suites cover;
and dt_parser.c (94.1% / 91.2%), dt_cg.c (96.6% / 89.2%) and dt_grammar.c
(94.6% / 91.5%) in the front end. Thirty-two libdtrace files are below 97%
raw on lines or branches, accounting for 1,484 uncovered lines and 1,437
uncovered branches. Anyone reading the 97% claim for libdtrace should read
it as "per component, after the documented waivers, including live suites",
with this offline raw measurement as the floor it stands on.

CLI after the printer change (2026-10-22): cli-dec5, 478/478 executable
cases pass, regression gate quiet. The explicit-cast printing of typed
integer constants changed no CLI expectation.

### Daemon interim note 3: 97/97 not reachable in hours (2026-10-22)

Live figure the agent stands behind (final5, HT-C excluded): 15,292/16,977
lines = 90.07%, 9,809/12,456 branches = 78.75%; dtracedctl 238/239 and
121/122. final7 (running, 2-3 h left) adds guest-installed and guest-rekey
flows, process-wide socket faults, 7 journal-fault operations, the
READDATA|CLEANUP refusal (fails before, passes after) and a guest shutdown
fix (SIGTERM 9.5 s -> 0.45 s; reg-stop-x42 before, reg-stop-x43 after).
Its 29 fault-oracle failures are harness artefacts already fixed (27
fresh-session effect-less steps, 2 load timeouts); one more full run
(final8) follows. Expected endpoint if stopped there: about 91-92% lines
and 80-82% branches (estimate). Open at final5: ~1,685 lines and ~2,650
branches, 868 of the lines in dtraced_directory.cc (about 80% error
returns, errno stores and their braces across ~120 functions), the rest in
send_elf (113), listen_dttransport (78), handle_elfmsg (49),
launch_program (48), accept_new_connection (44). The agent judges almost
all reachable with targeted fault tests or crafted journals; genuinely
unreachable candidates (bad_alloc on fixed-size containers, defensive
re-checks) are few and unreviewed. Reaching 97/97 with real oracles is
estimated at several days, each full measurement 5-8 h. Decision referred
to the user: stop at the final8 endpoint with the gap itemized as reachable
work, or continue.

Decision (user, 2026-10-22): commit at final8, continue after. The daemon
agent finishes final7 and a clean final8, hands back with measured figures
and all fail-before evidence; every area is then committed on
experimental/hypertrace with the daemon at its honest figure and its
remaining gap itemized as reachable work; the daemon push toward 97/97
continues afterwards as a follow-on.
