# libdtrace consumer-group coverage (2026-10-21)

Scope: the consumer/runtime side of libdtrace in
`cddl/contrib/opensolaris/lib/libdtrace/common/`, plus the library-side
instances of `usr.sbin/dtraced/dtraced_wire.h` and `dtraced_io.h` (tested,
not edited; the daemon agent owns them).  All testing is offline: the
library is opened with `dtrace_vopen()` against the dtrace(4) model in
`tests/consume-ingestion.c` (reused by `#include`, not edited), or through
preloaded interposer shims.  No device, kernel module, daemon, VM, install
or reboot was used.

Measurement: LLVM source coverage on the instrumented `libdtrace.so.2`
(`coverage-compiler-20261020`), all 19 existing offline suites plus the 7
new ones, fresh profiles only, merged while holding the shared build lock
(`lib-consumer-20261021/tools/measure.py`).  Final run:
`/usr/obj/5BSD-hypertrace-validation/lib-consumer-20261021/final3`, library
sha256 `ca4dbf2e7be0f1d1644484fbbaa515b420966bfefb75dc1b6594d4847d9f6996`,
all 26 suites exit 0.  "Before" is the whole-library baseline
`coverage-library-verify2-20261021`.

## Per-file results

| File | Lines before | Lines after | Branches before | Branches after | Functions after |
|---|---|---|---|---|---|
| dt_consume.c | 74.0 | 98.9 (2883/2916) | 62.9 | 96.0 (1494/1556) | 82/82 |
| dt_printf.c | 60.6 | 99.5 (1306/1312) | 53.3 | 97.9 (662/676) | 61/61 |
| dt_print.c | 53.5 | 97.7 (472/483) | 37.9 | 97.8 (227/232) | 18/18 |
| dt_aggregate.c | 64.4 | 98.0 (1286/1312) | 50.7 | 91.9 (688/749) | 55/55 |
| dt_subr.c | 64.9 | 99.1 (1203/1214) | 53.4 | 98.6 (621/630) | 67/67 |
| dt_program.c | 67.5 | 98.6 (1697/1721) | 55.4 | 96.3 (1061/1102) | 52/52 |
| dt_handle.c | 67.7 | 100 (283/283) | 39.6 | 95.3 (101/106) | 14/14 |
| dt_hashmap.c | 56.2 | 100 (215/215) | 41.3 | 98.9 (89/90) | 12/12 |
| dt_analysis.c | 57.7 | 100 (456/456) | 63.5 | 99.1 (220/222) | 13/13 |
| dt_dof.c | 79.2 | 99.1 (638/644) | 62.2 | 95.8 (182/190) | 17/17 |
| dt_map.c | 88.5 | 99.3 (303/305) | 73.7 | 87.1 (169/194) | 11/11 |
| dt_buf.c | 83.5 | 100 (85/85) | 65.0 | 100 (20/20) | 10/10 |
| dt_work.c | 81.9 | 100 (261/261) | 68.5 | 98.3 (177/180) | 10/10 |
| dt_sugar.c | 83.3 | 86.5 (193/223) | 72.0 | 77.7 (87/112) | 13/13 |
| dt_error.c * | 68.1 | 98.2 (160/163) | 55.0 | 94.3 (66/70) | 8/8 |
| dtraced_io.h (whole) | 23.6 | 28.1 | 59.3 | 83.3 | 6/13 |
| dtraced_wire.h (whole) | 10.6 | 10.6 | 72.2 | 94.4 | 9/54 |

\* dt_error.c moved mid-task to the typing agent, who is reworking
dt_set_progerr to return instead of exiting (user-approved).  Its figures
reflect that rework.

Library-reachable part of the dtraced headers (15 inline functions):
dtraced_io.h 75/82 lines and 45/54 branches; dtraced_wire.h 80/80 lines and
17/18 branches.  The rest of both headers is daemon-only code in dt_subr.c's
coverage unit and cannot be reached from library tests.

Files below 97% branches: dt_consume, dt_aggregate, dt_program, dt_handle,
dt_dof, dt_map, dt_sugar.  Every remaining outcome is waived below.  Most
are `assert()` false sides, native-device-only paths, or checks on kernel
input that were deliberately kept.

## Suites added (all take the world argument)

Add these to coverage-library-refresh.py as `(name, world)`:

| Suite | Files | Cases |
|---|---|---|
| consume-records | .c, -internal.c, .h, .py | 171 cases in 27 processes; ASan build plus a UBSan malloc/realloc/ioctl/sysctl interposer build |
| printf-conversions | .c, .py, -shim.c | 311 checks, including 13,824 integer and 600 float conversions compared with C snprintf; 1 known failure in dt_cc.c, recorded without failing the suite |
| printf-faults | .c, .py | 9 scenarios, 93 injected allocation failures (no ASan) |
| aggregate-walk | .c, -vm.c, .py | 103 cases after round 2 (ASan build plus an unsanitized fault/no-device build) |
| program-properties | .c, .py | 120 cases: MurmurHash3/probing reference model, independent DOF decoder, dtrace_program_compiled_digest identity, fault sweeps |
| subr-handle | .c, .py | 25 groups, 326 checks |
| subr-faults | .c, .py, -shim.c | 10 groups, 305 checks; N-th call failure for malloc, send/recv, poll, socket, sysctl, pthread_create, pread, … |

program-verify-mutation.c/.py gained 22 `bottom-rtype` mutants, and the
.py now fails on any verdict mismatch.  consume-ingestion.c/.py are
unchanged.

The expected values come from independent oracles:
- the kernel record-layout rules in dtrace.c;
- C printf/snprintf;
- aggregation maths and sort orders derived by hand from the documentation;
- libxo JSON parsed structurally;
- Python and C reference models (hash map, DOF loader rules);
- dladdr;
- CTF layouts built with libctf.

No expected value was pasted from observed output.

## Bugs fixed (regression case; it failed before the fix and passes after unless noted)

dt_consume.c / dt_work.c / dt_buf.c (consume-records)
- dt_trunc: a bad value size returned EDT_BADNORMAL instead of EDT_BADTRUNC [trunc-bad-value-size]
- agghist with avg()/stddev() aborted the process on an assert [agghist-avg-stddev, agghist-cleared-avg]
- dt_print_agg/dt_format_agg returned -1 without setting errno, leaving a stale errno [buffered-aggregations, oformat-printa-bad-stack-key, malloc-failure-aggregations-oformat]
- Structured output printed "(null)" and reported success when an allocation failed [malloc-failure-records-oformat]
- ustack helper strings that are not NUL-terminated were over-read, now bounded with strnlen [ustack-no-frames-and-strtab-end, oformat-edges]
- dtrace_uaddr2str retry loops were off by one [nodev-uaddr-256, nodev-uaddr-256-oformat]
- dtrace_go turned EDT_NOMEM into ENOMEM after a dt_options_load failure [go-allocation-sweep; the pre-fix log was lost to a concurrent rebuild]
- BEGIN buffer leaked when the CPU count could not be read [cpu-count-begin-end; the leak is not observable]
- dt_ndigits signed overflow above 10^18 [aggpack-extreme-buckets; not observable at -O0]

dt_printf.c / dt_print.c (printf-conversions, printf-faults)
- Formats without a size prefix gave records the wrong width or float type [width-*, float-conversions, float-L-on-double]
- %P and %I inverted the getservbyport_r/gethostbyaddr_r result; a resolver error dereferenced NULL; inet_pton returning 0 counted as success; a hostent leaked [port-*, inet4-*, inet6-*, inet-no-lookup-for-text, inet6-hostent-released]
- %T used the ISO week-based year [time-T-calendar-year, time-T-year-start]
- '0' after '-' cancelled left justification [pickle-2, pickle-4]
- dtrace_sprintf freed its buffer twice [sprintf-error-buffer-released]
- printa: errno returned as the walk result; joined walk continued after an abort [printa-buffered-abort, printa-joined-abort]
- %a/%A retry was off by one [addr-long-symbol-256, addr-long-symbol-311]
- %k on a record that is not a stack hit assert(0); now EDT_DMISMATCH [stack-not-a-stack]
- Wrong "two stars" message [check-two-stars]
- %wc/%ws passed through untranslated [pickle-13, wide-*-w]
- print() of a 128-bit integer overflowed the stack [print-integers]
- Bit-field spill and unaligned-byte errors [print-bitfields]
- Off-by-one and negative library index in the pid module path [print-pid-module-bad-0, -1]
- dtrace_format_print leaked the module name
- Invalid JSON for an invalid member, floats and large type IDs [format-print-invalid-member, format-print-floats, print-model-structure]
- print() with buffered output wrote to a NULL FILE; output is now emitted through a single dt_printf (keeps pa_xo) [print-buffered; print-discarded not run before the fix]
- Structured print() of a char array silently dropped the value on an allocation failure; now EDT_NOMEM [printf-faults print-value; consume-records malloc-failure-print-oformat]

dt_aggregate.c (aggregate-walk)
- clear() (walk and API) zeroed the lquantize/llquantize parameter word, causing SIGFPE or a mismatch later [clear-api-keeps-parameters, clear-walk-keeps-parameters]
- Joined zero-fill gave llquantize parameter 0 [joined-histogram-zero, joined-never-fired]
- aggpercpu empty copies lost the lquantize/llquantize parameter [percpu-copies]

dt_program.c / dt_dof.c / dt_analysis.c / dt_hashmap.c (program-properties, program-verify-mutation)
- Hash map: pointer keys were compared by content on insert and delete [hashmap-pointer-identity]
- Hash map: the aligned hash path depended on the key's address [hashmap-alignment-independent]
- dof_construct_kvartab called errx() on malloc failure, killing the consumer; it also leaked per DIFO [fault-exec 6→0 exits, fault-dof 1→0]
- Analysis graphed clause-local variables as probe self-edges [graph-clause-local]
- An impossible assert in dtrace_graph_program
- Call scan began at instruction 1 and the label lacked a terminator [graph-call-first-instruction; passed before the fix too]
- Verifier (user-requested): a BOTTOM base rtype accepted any new rtype.  New rule in dt_prog_bottom_rtype_ok():
  - the result kind must be BOTTOM, CTF or STRING;
  - a BOTTOM result must keep its flags and size, and may only change its CTF kind to the linker's CTF_BOTTOM_TYPE;
  - a STRING result must have the original flags plus DIF_TF_BYREF;
  - a CTF result must be the substituted void/int, or keep its flags (optionally plus BYREF) with a by-value size of 1/2/4/8 or the compiled size, or a nonzero by-reference size.
  - 22 mutants; 11 were wrongly accepted before the fix, all 22 match after [program-verify-mutation bottom-rtype-*; before log in D-regressions/bottom-rtype-before-prefix.txt]

dt_subr.c / dt_map.c / dt_handle.c (subr-handle)
- dtrace_addr2str truncated module-only strings [addr2str]
- dt_attr_str indexed the terminating NUL [attributes]
- dt_version_str2num overflow accepted 4294967297.0 [versions]
- dt_map: NULL table checked before use (no behaviour change)
- subr-handle's progerr group was updated to the reworked return-based dt_set_progerr contract.  No dt_error.c edits after the reassignment; get_randname (unused) was removed earlier.

## Redundant checks removed (user decision; local proofs only, assert()s kept, no functions removed)

- dt_consume.c:
  - the second carry term in dt_add_128;
  - the constant-min else branch in lquantize_packed;
  - dt_print_sym's format parameter (every caller passes NULL);
  - the repeated dt_active check in dtrace_consume_consumer.
- dt_work.c: the `!dt_stopped` checks in dtrace_status, because dtrace_stop is idempotent.
- dt_printf.c:
  - ctf_array_info/ctf_type_encoding failure tests right after a kind check on the same ID;
  - `q = *p ? p+1 : p` in the parse loop.
- dt_print.c: encoding and array-info failure branches for kinds fixed by the dispatch table.
- dt_aggregate.c:
  - bundlecmp's equal-representative-key fallthrough;
  - the joined fallback loop bound (assert kept).
- dt_program.c (non-verifier code only):
  - the dt_vprog_memorize and dt_vprog_reorganize argument guards;
  - the ostp==stp branch and the abort();
  - the addargload "list full" check (now a _Static_assert: at most 5 of 10 slots are used).
- dt_dof.c: the `data != NULL` check in dof_add_usect.
- dt_analysis.c: an unreachable return after an exhaustive switch.
- dt_sugar.c:
  - the condid==0 return;
  - the always-true num_conditions==0 test;
  - the dead dn_acts==NULL block (now an assert).
- dt_handle.c: dt_droptag's unknown-kind fallback.
- dt_map.c: the slot-occupied checks in dt_epid_add/dt_aggid_add (now asserts).
- dt_subr.c:
  - impossible conditions after strtol;
  - two constant-length checks replaced by _Static_assert;
  - dtrace_send_elf_impl's parent parameter checks.

No verification check was removed or weakened.

## Remaining gaps (waivers)

- **assert() false sides.** These are the majority in dt_aggregate (~38), dt_map (20), dt_handle (5), dt_program, dt_hashmap and dt_analysis.
- **Native-device-only paths.** dt_aggregate.c 341-377 and 395-414 (usym/umod/mod when dt_vector == NULL) need /dev/dtrace and a grabbed process.
- **Kernel-input checks, kept on purpose.** dt_consume.c `dtagd_nrecs == 0` at 2446/7, 2514/5, 2529/30, 2550/1, 3104/5 and 3139/40, and the key loops at 2918F and 3028F.  dt_printf.c 1547-1548 and 2205.  dt_map.c 375F.
- **Structured-output paths that cannot fail.** dt_consume.c 2634-2640, 2938-3000, and 3467-3524 (dt_format_* always return 0).
- **Other unreachable code in dt_consume.c.** 2806/7 (aggpack default), 118T, 140F, 1312F, 1399F, 1610F (exported immstack keeps its format handling), 3557F.
- **dt_work.c 398F, the ECANCELED arm.** Proving it unreachable depends on dt_map.c and on the vector's return values, so the proof is not local.
- **dt_aggregate.c.** The 8 aggsortrev macro sides at 772/775, 832/835 and 930/937; removing them would change shared comparator semantics.  Also valcmp's default arm at 971, which is reachable in principle through a malformed AGGDESC in joined zero-fill.
- **dt_program.c.**
  - Duplicate verifier checks at 1579-1628 and 1037, kept by direction.  Removing them is the user's decision; deleting verifier checks was refused by the permission classifier.
  - Other unreachable or impractical branches:
    - 1231 (strsize lookup);
    - 1343 (overflow guard);
    - 1442;
    - 153 (xrefs NULL with a nonzero length);
    - 666 (needs more than 65,536 probe targets);
    - 541 and 611 (asserts).
  - Reachable but not yet tested: BOTTOM-rule sizes 1/2 (925-926), and the ULOAD/UULOAD NOP-elision false sides (1021/1023/1056).
- **dt_dof.c 742 and 849.** Format-size failures that cannot happen.
- **dt_map.c.** dt_format_lookup and dt_strdata_lookup range/NULL checks are kept because these exported functions have callers in other files.
- **dt_subr.c.**
  - pcb_sargv != argv (global parser state);
  - a second vsnprintf failure;
  - the arc4random all-zero ID retry;
  - trylock errors other than EBUSY;
  - queue teardown states;
  - SHA failure at 1698F.
- **dt_sugar.c.** The visitor cases for FREE/AGG/INLINE/MEMBER/XLATOR/PROVIDER/PROG/default (22 outcomes).  The parser cooks some nodes while building, so the call site alone does not make the proof airtight.  The code is the same as upstream FreeBSD.
- **dt_print.c.**
  - 609-621: the enum-size cases are dead because libctf ctf_type_size(ENUM) always returns the int size, so packed enums are misread until libctf is fixed.
  - 922: fclose of a memstream failing.
- **dt_printf.c.**
  - 91 and 469: the target macro is always defined.
  - 855-859 and 1246-1247: built-in types are always present.
  - 243: anonymous typedef name.
  - 484: needs a real process with a symbol of 256 or more characters.
  - 1170, 1588 and 1757-1758: these depend on format construction in other functions.
- **dt_error.c.** Owned by the typing agent from mid-task.
- **dtraced_io.h.** Clock values a correct kernel never returns; EWOULDBLOCK equals EAGAIN on FreeBSD; a two-fault race.
- **dtraced_wire.h.** A NULL hello message.

## Bugs reported in files not owned by this group

- **dt_cc.c (joined printa).** Every %@ is validated against the first aggregation's function, so after a count() a sum's %@d prints as unsigned.  Known failure printa-count-first in printf-conversions.  Proposed fix: validate each %@ against its own aggregation.
- **dt_hypertrace_linker.cc:384 and dt_typing_var.cc:400/457/480 (typing agent).** CTF *type ids* are stored in `dtdt_ckind`, which is a CTF *kind*.  This blocks the `dtrace -E` round trip of `dtrace:::BEGIN { x = 1; } dtrace:::END { trace(x); }`.  Proposed fix: `tf->getKind(ctfid)` at those sites.
- **The `-E` "typecast was not set to nop (!= 84)" rejection.** The diagnosis is that the verifier is right: the linker always replaces TYPECAST with a NOP (dt_hypertrace_linker.cc:587-592), so the host received an unlinked program.  The suspected cause is dtraced routing the base ELF instead of the linked one; this needs daemon-side confirmation.  Evidence: D-regressions/typecast-diagnosis.{c,txt}.  No CLI regression case was added, because the round trip needs both outside fixes first.
- **dt_error.c (typing agent).**
  - When the message cannot be formatted, only an empty line reaches stderr (suggest printing dp_err after the fallback is set).
  - A full 4095-byte dp_err silently drops the "; reason" for a failed guest forward.
- **libctf.** ctf_type_size ignores the recorded size for enums.
- **libxo.** Raw control characters inside JSON strings.
- **Observation.** dt_vprog_reorganize leaves third and later clauses for the same guest probe in reverse order.

## Round 2 (2026-10-21, coordinator request: close remaining branch gaps)

Final round-2 measurement: `lib-consumer-20261021/final4`, library sha256
`f3953208503a7954122ec61d17ef40e01104e5655cb1b904edf118e55b4314a4`, all 26 suites
exit 0 (aggregate-walk now 103 cases, program-properties 122, subr-handle 328 checks).
This supersedes the per-file table above.

| File | Lines | Branches | Functions |
|---|---|---|---|
| dt_consume.c | 98.9 (2887/2920) | 96.3 (1499/1556) | 82/82 |
| dt_printf.c | 99.5 (1306/1312) | 97.9 (662/676) | 61/61 |
| dt_print.c | 97.7 (472/483) | 97.8 (227/232) | 18/18 |
| dt_aggregate.c | 99.8 (1318/1320) | 93.9 (707/753) | 55/55 |
| dt_subr.c | 99.0 (1208/1220) | 98.4 (624/634) | 67/67 |
| dt_program.c | 98.7 (1608/1630) | 96.9 (1079/1114) | 52/52 |
| dt_handle.c | 100 (283/283) | 95.3 (101/106) | 14/14 |
| dt_hashmap.c | 100 (215/215) | 98.9 (89/90) | 12/12 |
| dt_analysis.c | 100 (456/456) | 99.1 (220/222) | 13/13 |
| dt_dof.c | 99.5 (641/644) | 96.3 (183/190) | 17/17 |
| dt_map.c | 99.4 (307/309) | 88.3 (173/196) | 11/11 |
| dt_buf.c | 100 (85/85) | 100 (20/20) | 10/10 |
| dt_work.c | 100 (261/261) | 98.9 (176/178) | 10/10 |
| dt_sugar.c | 86.5 (193/223) | 77.7 (87/112) | 13/13 |
| dt_error.c (typing agent) | 96.5 (165/171) | 93.2 (69/74) | 9/9 |

dt_program.c measured 97.1% (1072/1104) in fork D's run `D-r2final`.  In final4 it
measures 96.9%, because the typing agent changed the file again between the two runs.

Round-2 bugs fixed (regression case; it failed before the fix and passes after):
- **dt_consume.c.** A malformed AGGDESC with only the value record (nrecs 1) aborted on
  `assert(aggact != 0)` in dt_print_aggs and dt_format_aggs.  It is now refused with
  EDT_BADAGG [consume-records aggdesc-value-only, aggdesc-value-only-oformat; SIGABRT
  before, log A-work/prefix-value-only.log].
- **dt_aggregate.c.** A malformed AGGDESC for a never-fired variable in joined zero-fill
  reached valcmp's `assert(0)`.  It is now refused with EDT_BADAGG, and the aliased column
  pointers are cleared first [aggregate-walk joined-zero-fill-unknown-action; SIGABRT
  before, C/prefix-badagg-r11].
- **dt_map.c.** dt_aggid_add accepted an AGGDESC with zero records.  dt_aggregate_snap
  then read `dtagd_rec[-1]`, which overlays the header and is not caught by ASan.  It is
  now freed and refused with EDT_BADAGG before it is cached [subr-handle
  aggdesc-no-records; before: "rc 0, cached 1", E-work/pre-fix-aggdesc.log].
- **dt_work.c.** The unreachable ECANCELED arm was removed, because
  dtrace_consume_consumer returns only 0 or -1 (proved over all of its return sources).

Round-2 coverage additions:
- The device-only usym/umod/mod normalization in dt_aggregate.c is now covered through
  dtrace_fdopen on a regular file with an ioctl interposer, so dt_vector is NULL, plus a
  read-only libproc grab of the test's own process.  The oracles are dladdr,
  kinfo_getvmmap and kldstat [aggregate-walk nodev-key-normalization; new helper
  aggregate-walk-vm.c].
- Exported dt_print_immstack with a caller format [immstack-caller-format].
- The BOTTOM-rule by-value sizes and the ULOAD/UULOAD NOP-elision cases
  [verify-difo-bottom-rtype-sizes].
- dtrace_dof_create's EOVERFLOW on a format of UINT_MAX bytes or more
  [dof-format-overflow].
- The realloc failure in dt_vprog_group [fault-vprog].
- AGGDESC with one record [aggdesc-value-only in subr-handle].

program-properties and program-verify-mutation were rerun against the typing agent's
dt_vprog_* rewrite, and both pass.  The rewrite only tightens the BOTTOM rule further.

Round-2 waivers, beyond the assert() false sides, which remain in every file:
- **dt_sugar.c (22 visitor outcomes): proved unreachable.**  dt_compile_sugar runs only
  at dt_cc.c:2550, on clauses straight after yyparse.  Inside a clause the grammar builds
  only IDENT, INT, STRING, TYPE, FUNC, OP1/2/3, DEXPR/DFUNC, IF, PDESC and CLAUSE nodes:
  - member access and xlate are OP2;
  - sizeof and offsetof fold to INT;
  - DT_NODE_AGG is created only when an ident is cooked;
  - INLINE, MEMBER, XLATOR, PROVIDER and PROG come only from declarations or the root;
  - the parse-time dt_node_cook calls are only in dt_node_inline and dt_node_xlator;
  - FREE is never relinked.
  The code is kept for parity with upstream FreeBSD.
- **dt_map.c.**
  - Lines 177 and 380: nrecs == 0 arms inside a branch that requires nrecs > 1.
  - Lines 302/305 and 482/485: dt_epid_add caches a description only after
    dt_strdata_add has loaded every format, and the callers check the same action kinds,
    so these lookups never see a format above the maximum or a NULL table.  The checks
    are kept because the functions are exported.
- **dt_consume.c.**
  - The `nrecs == 0` checks at 2446, 2514, 2529, 2550, 3113 and 3148 are now provably
    dead, because dt_aggid_add rejects a description with zero records.  They are kept
    as defensive checks on kernel input.
  - The structured-output paths that cannot fail and the other unreachable outcomes are
    as listed above.
- **dt_aggregate.c.**
  - 8 aggsortrev macro sides, at 772/775, 832/835 and 930/937.
  - valcmp's default arm, now unreachable from every path.
- **dt_program.c.**
  - The verifier's duplicate checks at 1590-1639 and 1048, pending the user's decision.
  - Branch 153.
  - Branch 666, which needs more than 65,536 probe targets.
  - Branches 1242, 1354 and 1453.
  - Branch 1843: snprintf needs at most 447 of 454 bytes, so it cannot truncate.
  - Branch 1922: both callers check for a non-NULL DIFO.
- **dt_dof.c 847.**  A second, identical format pass cannot fail once the first has
  succeeded.
- **dt_work.c.**  2 outcomes were not individually identified in round 2.

Round-2 evidence (under `lib-consumer-20261021/`): `final4`, `A-final5`, `C/m-round2`,
`C/r12`, `D-r2final`, `D-r2m`, `E-m6`, `E-m7`, `E-work/sh6`.

## Evidence

All under `/usr/obj/5BSD-hypertrace-validation/lib-consumer-20261021/`:

- `final3/`: final measurement, with files.json, coverage.json and per-suite logs.
- `show-base3/`: baseline listings.
- Per-fork measurements and before/after regression logs:
  - `A-final3`, `A-work`;
  - `B-final4`, `B-regress`, `B-prefix-lib`;
  - `C/m-simplify`, `C/prefix-*`;
  - `D-final3`, `D-regressions`;
  - `E-m5`, `E-work`.
- `tools/measure.py`: the measurement tool.
