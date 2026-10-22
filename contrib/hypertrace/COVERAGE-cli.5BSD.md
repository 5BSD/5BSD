# DTrace CLI and runtime support object coverage (2026-10-21)

Owner: CLI/drti coverage agent. The coordinator merges this record into
COVERAGE.5BSD.md. Evidence directories are under
`/usr/obj/5BSD-hypertrace-validation/` and are prefixed `cov-cli-`. Only what
was run is reported. Offline only: no tracing device, module, VM, installed
daemon, installation or reboot was used.

## Result summary

Final evidence: `cov-cli-final-20261021` (405/405 executable cases passed,
historical `cli-offline.py` 28/28 merged as baseline, LLVM merge/export logs
empty, production hashes unchanged during the run, regression gate passed).

| Component / file (full mapped denominators) | Lines | Branches | Functions |
| --- | ---: | ---: | ---: |
| `cmd/dtrace/dtrace.c` baseline (`cov-cli-baseline-20261021`) | 458/3172 14.44% | 216/1660 13.01% | 11/70 |
| `cmd/dtrace/dtrace.c` final | **3008/3177 94.68%** | **1464/1667 87.82%** | **69/70** |
| `cmd/dtrace/dtrace_identifiers.h` final (baseline 0/57, 0/46, 0/3) | 53/57 92.98% | 33/46 71.74% | 3/3 |
| `cmd/dtrace/hypertrace_frame.h` final (baseline 0/48, 0/60, 0/2) | 47/48 97.92% | 47/60 78.33% | 2/2 |
| CLI component total (three files) | 3108/3282 94.70% | 1544/1773 87.08% | 74/75 |
| `drti.c` runtime support object (`cov-cli-drti-20261021`) | 86/89 96.63% | 45/46 97.83% | 3/3 |

dtrace.c by function origin (names absent from FreeBSD HEAD's dtrace.c are
HyperTrace-added; the two rows sum to the file totals):
HyperTrace-added 1456/1599 lines (91.06%), 690/834 branches (82.73%),
38/39 functions; FreeBSD-origin 1552/1578 lines (98.35%), 774/833 branches
(92.92%), 31/31 functions. Baseline: HyperTrace 0/1598, FreeBSD 458/1574.

Mapped dependency headers compiled into the executable are reported
separately and are not part of the CLI denominator (owned by the daemon
work): `dtraced_io.h` 75/264 lines, `dtraced_wire.h` 267/736 lines.

None of the CLI files meets 97% lines and branches. The itemized remainder is
below; most of it is dead, configuration-dead or defensive code that no
offline (or live) input can reach. A scope decision is needed (see
"Decisions needed").

## Method

`contrib/hypertrace/tests/coverage-cli.py OUTPUT [--only REGEX] [--skip-baseline]`
(cases in `coverage-cli-cases.py`; harness `cli-model-shim.c`,
`cli-fake-dtraced.c`; neither is instrumented or counted).

- The executable is rebuilt from the maintained `cddl/usr.sbin/dtrace` make
  commands (`make -n -B` against the shared coverage object tree; only the
  `cc`/`objcopy` steps run, in `OUTPUT/build`, with the coverage wrappers).
  Shared libdtrace/libctf/libproc/librtld_db/drti builds are used read-only
  and hashed (libdtrace `6227951f…`). The shared tree's own `dtrace` is not
  rebuilt.
- Every case runs the real binary and asserts its exit status and stdout /
  stderr: exact where dtrace.c formats the text, fragments or anchored
  regular expressions where libdtrace formats it or threads interleave lines.
  Expected text comes from dtrace.c formats and D semantics, not captures.
- Boundary (LD_PRELOAD shim): `dtrace_open()` → real library with
  NODEV|NOSYS forced, or `dtrace_vopen()` with the dtrace(4) model of
  `consume-ingestion.c` (snapshot compiled in, hash recorded; the shim adds
  typed PROBEARG answers for one probe, VPROBE_CREATE/AUGMENT/guest-ENABLE
  handling, post-GO option changes, delays and per-command failures).
  Scripted firings at GO/STOP/Nth STATUS/BUFSNAP; D is never executed.
  `connect()` to `/var/ddtrace/sub.sock` → private scripted daemon or
  refused. `/dev/dtrace*`, `/dev/ksyms`, `/boot`, `kldload()` refused and
  logged; `kldnext()` reports no modules. `/dev/dtrace/hypertrace` gate
  queries are modeled. `pdself()`/`PDIOC_GET_BIRTH_IDENTITY` are modeled
  because the running host kernel (built 2026-10-07) returns ENOTCAPABLE
  for them. `posix_spawnp("nextboot")` runs `/usr/bin/true|false` after
  recording argv. `syslog()` is captured. Children start without the shim.
- Faults: libc faults fire only for calls made from the executable after
  `main()` starts; a few libdtrace entry points have API faults used only
  where no model/daemon behavior can make the library fail
  (`dtrace_program_compiled_digest`, `dtrace_getopt`, `dtrace_setopt`,
  `dtrace_elf_create`, `hypertrace_link`, `dtrace_elf_parse`,
  `dtrace_get_srcident`, `dtrace_vprog_from`, `dt_prog_verify`, handler
  registration, header generation, DOF creation, aggregation printing,
  options update). Every case requires each injected fault to have fired.
  `abort()` is logged and mapped to `exit(134)`; cases assert the logged
  abort. A monotonic clock jump (count- or file-triggered) expires pending
  deadlines deterministically.
- Real multi-process flows: host `-E` consumer ↔ scripted daemon (program
  registration, ELF deliveries, identified ACKs, derived-program
  publication, drain/stop challenges, stop commits, execution receipts,
  KILL revocation, reconnects); host ↔ guest loop where the same binary runs
  `-Y derived.elf,guest` and its outbound reply is returned to the host;
  `-M` listing; `-c`/`-p` process control (slow rates, see libdtrace note).
- Only passing-case profiles are merged; profiles of processes killed by a
  signal (the known race below) are excluded and listed in `summary.json`.
- Regression gate: frozen denominators and floors in `REGRESSION`
  (dtrace.c ≥2997/3177 lines, ≥1453/1667 branches, ≥69/70 functions;
  identifiers ≥53/57, ≥33/46; frame ≥47/48, ≥47/60).

Case groups (405): exec 56, host consumer 162, guest 35, anon 20, opt 19,
listvms 14, link 12, proc 11, setopt 11, list 10, header 7, fix/regression
23 (incl. 16 lost-wakeup repetitions), misc 25.

## Defects fixed in dtrace.c (each with regression cases)

Evidence: `cov-cli-fixes-before-20261021`, `cov-cli-fixes-after-20261021`,
`cov-cli-stress1-20261021` (before) / `cov-cli-stress3-20261021` (after),
cumulative diff `cov-cli-round3-20261021/dtrace.c.session.diff`.

1. `-D` silently ignored (CADETS import dropped the second-pass `case 'D'`);
   restored. `fix-define-symbol`.
2. `-g file` documented but rejected (`g:` missing from the option string;
   graph code dead). Added; dtrace.1 now documents `-g`. `fix-graph-file*`.
3. `-x hypertrace_session_file` validation ran before the option was parsed
   (dead check); moved after pass 2. `fix-session-file-requires-host`.
4. `handle_signals()` passed `sigset_t` by value to `%s` (SIGSEGV while
   printing). `fix-signal-thread-sigmask`.
5. `fatal("…%s", __LINE__)` int passed to `%s` (benchmark build only).
6. `vm_name == NULL` on an array (always false; "host" never printed).
7. Diagnostic errno hygiene: 35 `fatal()` formats appended an unrelated or
   duplicate `strerror(errno)` ("No error: 0", "…: X: X"); terminated where the
   text already carries the error or errno is meaningless; `-1` message now
   states the enforced limit. pthread init failures now report the returned
   error instead of stale errno. `send_kill()` sets EBADF.
8. **Lost wakeup**: three threads wait on `g_pgpcond` but five sites used
   `pthread_cond_signal`; the execution loop could miss a delivered program
   (6/40 host runs hung under load before; 80/80 passed after). All sites
   now broadcast. `fix-wakeup-*`.

Eleven existing extraction harnesses that compile regions of dtrace.c were
rerun against the edited source and pass (`cov-cli-extraction-check-20261021`).

## Open defects and design questions (not fixed)

- **fatal()/exit while other threads use the handle**: `fatal()` on a
  secondary thread, or on the main thread while the output worker runs,
  closes `g_dtp` under a concurrent `dtrace_sleep/status/work`. Reproduced as
  SIGSEGV/SIGBUS; in the final run 6 of the cases recorded as `known_defect`
  crashed (their profiles are excluded). Needs a design decision (serialize
  all handle use under `g_dtpmtx`, or exit without closing off-thread).
- Default `temporal=yes` (set by main) makes `dtrace_consume_quiesced()`
  refuse every drain challenge; drains succeed only with `-x temporal=no`
  (`host-drain-temporal-refused` vs `host-drain-regular-file`).
- `-y FILE` starts tracing without enabling the program's ECBs, then the same
  command continues into the `-E` host consumer path (`elfrun-*`).
- An unidentified duplicate host delivery is a new program (lookup compares
  stored `dp_ident` with the incoming `dp_srcident`) and derives a second
  guest program. KILL revocation is lost if the daemon connection drops
  during shutdown (`loop-reconnect-loses-kill`).
- `-G` without objects or `-64` emits an ILP32 provider object that cannot link
  with the LP64 runtime object (stock behavior; `link-default-model-no-objects`).
- Cosmetic: several `fprintf(stderr, …)` diagnostics in process_new_pgp /
  listen_dtraced lack a prefix or newline.

For the coordinator (libdtrace, not edited): `dtrace_sleep()` returns before
draining process notifications once its earliest deadline has passed, so
with fast rates `-c` exits are never reported; `dt_provider.c` keeps
`DTT_FL_USER` from a previous argument when a type fails to resolve
("userland (unknown)"); probe-mismatch messages print the five-part
description (":nosuch:::probe"). Ambient: the installed `/lib/libutil.so.10`
USDT object opens `/dev/dtrace/helper` from its destructor even with
`DTRACE_DOF_INIT_DISABLE=1` (refused by the shim; not blocked by the
historical `cli-offline.py` shim).

## Remaining dtrace.c gap (169 lines) with reasons

- Dead (never called): `checkmodref()` 28 lines.
- Configuration-dead (benchmarks disabled; `dt_bench_*` are constant macros):
  6 lines (1043, 1050, 1063, 1430, 2894, 2897).
- Defensive/unreachable by construction, about 74 lines: `process_new_pgp`
  guest/epoch guards (pgpl_valid and lookups guarantee them), vmid-claim
  branch (lookups require equal vmid), SHA256 NULL, argument guards in
  receipt/session helpers, reaper-state inconsistencies and pid ≤ 1,
  non-EBUSY trylock, unterminated client name (decoder already requires a
  NUL), non-32/64 ELF class, `pgpl_valid(NULL)`, notice limit 65536,
  structural lines (4345, 4456), PS_LOST (set-id exec is not lost when
  unprivileged on FreeBSD).
- Not reached; analysis indicates unreachable: host-path "found a valid pgpl"
  (29 lines; duplicate replies are diverted to the AGAIN path).
- Interleaving-dependent (≈18): session-stop exits inside the worker loop,
  interrupted frame/reconnect races, impatient record abort, listing
  interrupt, deadline expiry while waiting for locks.
- Not targeted (≈10): clock-index faults for five deadline computations,
  reemit close failure, process-control message notification, two buffered
  handler NULL fields; crash-only lines of known-defect cases (514, 3019,
  3026, 3070) whose profiles are excluded.

If dead and defensive code were removed (or formally waived) the reachable
denominator would be about 3069 with 3008 covered (≈98%); without a decision
the honest figure is 94.68%.

## Runtime support object (drti.c)

`cov-cli-drti-20261021` (existing `drti-offline.py`, 19/19, source hash
`7850e9d5…` unchanged): 86/89 lines, 45/46 branches, 3/3 functions. The three
lines and one branch are the `LM%lu\`` module-name branch, unreachable on
FreeBSD where `lmid` is constant 0 (illumos-only). drti.c lives in
libdtrace/common (coordinator-owned); proposal: guard that branch with
`#ifdef illumos`, which leaves 86/86 lines.

## Generated compiler sources

`coverage-cli.py OUTPUT --generated-from coverage-library-verify2-20261021`
(read-only use of the coordinator's library evidence; refuses a library or
generated-source hash mismatch). Evidence: `cov-cli-generated-20261021`.
Physical figures are llvm-cov lcov line records (these differ slightly from
the summary's line totals).

| Generated file | Physical lines / branches | Attributed to input | Generated-only (skeleton/tables) |
| --- | --- | --- | --- |
| dt_grammar.c (yacc) | 957/1311, 386/480 | dt_grammar.y: 282/364 lines, 1/2 branches | 675/947, 385/478 |
| dt_lex.c (lex) | 1015/1772, 591/1070 | dt_lex.l: 379/531 lines, 485/838 branches | 450/805, 106/232 |
| dt_errtags.c (mkerrtags.sh from dt_errtags.h) | 3/3, 3/4 | none (no line mapping) | 3/3, 3/4 |
| dt_names.c (mknames.sh from sys/dtrace.h) | 8/61, 61/114 | none (no line mapping) | 8/61, 61/114 |

Attribution follows the `#line` directives emitted by yacc/lex; skeleton and
table code stays in the generated-only accounting.

## Decisions needed

1. Scope for 97%: delete `checkmodref()`; treat benchmark-only code as a
   separate configuration; convert or waive the defensive branches listed
   above. Without this, dtrace.c cannot reach 97% lines.
2. The fatal()/handle-close race (design change in dtrace.c threading).
3. Whether HyperTrace host consumers should default `temporal` off so drain
   challenges can succeed.
4. Intended `-y` semantics (run-only vs continue into the host consumer).
5. drti.c illumos-only branch guard (coordinator-owned file).

## Build frontend note (AGENTS.md)

No build inputs, staging, signing or publication requirements changed; the
fixes are behavioral corrections inside `cddl/usr.sbin/dtrace`.
`/usr/src/usr.sbin/bsd-build` needs no update for this work (not edited).

## Evidence index

`cov-cli-baseline-20261021` (baseline), `cov-cli-fixes-before/after-20261021`,
`cov-cli-stress1-20261021` / `cov-cli-stress3-20261021` (lost wakeup),
`cov-cli-round2-20261021`, `cov-cli-round3-20261021`,
`cov-cli-final-20261021` (final), `cov-cli-drti-20261021`,
`cov-cli-generated-20261021`, `cov-cli-extraction-check-20261021`.
Development runs `cov-cli-dev*-20261021` and `cov-cli-dbg*` are exploratory
and not used for reported figures.

## Follow-up (2026-10-21): handle-close race and temporary files

Final evidence: `cov-cli-final6-20261021`. 454/454 cases pass. The historical
`cli-offline.py` 28/28 is merged as baseline. Regression gate passes, and no
profile was excluded for a signal exit. Runs now use a private snapshot of the
shared libraries (`libsnap/`) and refuse results if a library changes during a
run. An earlier attempt was invalidated by a concurrent libdtrace rebuild.
dtrace.c diff for this follow-up: `cov-cli-final6-20261021/dtrace.c.followup.diff`
(source sha256 `02db0d20…`).

| File | Lines | Branches | Functions |
| --- | ---: | ---: | ---: |
| `dtrace.c` (new denominator, 9 new helpers) | 3101/3297 94.06% | 1494/1715 87.11% | 78/79 |
| `dtrace_identifiers.h` | 53/57 | 33/46 | 3/3 |
| `hypertrace_frame.h` | 47/48 | 47/60 | 2/2 |

HyperTrace-added code is 1542/1715 lines. FreeBSD-origin code is 1559/1582 lines.
The remaining-gap classes listed above are unchanged. The busy-window "found a
valid pgpl" re-parse (AGAIN path) is no longer reachable now that handle use is
serialized. That case now asserts the serialized outcome.

### 1. fatal()/dfatal() handle-close race (fixed)

- Every use of `g_dtp` is serialized by `g_dtpmtx` through
  `dtp_lock()/dtp_unlock()`, which keep a per-thread hold count. Once the
  signal thread exists, this covers the output worker loop, `setup_tracing()`,
  `exec_prog()`, `process_new_pgp()` (via `execute_new_pgp()`), the
  receiver's parse/verify/derive/ELF-create calls, the replay path, the drain
  and stop handlers, `-y`/`-Y` and the list and exit paths.
- `g_dtpmtx` is recursive and initialized first in main. fatal() can therefore
  run on a thread that already holds it without deadlocking.
- Lock order is `g_pgplistmtx` before `g_dtpmtx`. No thread holding the handle
  lock waits for `g_pgplistmtx`. `prochandler()` runs inside `dtrace_sleep()`
  under the handle lock, so it now sets `g_stop` and a deferred wakeup. The
  worker broadcasts that wakeup after releasing the lock.
- fatal() and dfatal() are single-shot via an atomic flag. Another thread that
  reaches them releases its holds on `g_dtpmtx` and then blocks. Re-entry on the
  terminating thread calls `_exit(1)`.
- The winning thread unlinks tracked temporary files, then takes the handle
  lock and calls `dtrace_close()`. That waits for the current user and restores
  or continues controlled processes as before. The thread then exits while still
  holding the lock, so no thread can touch the closed handle. `g_dtpmtx`,
  `g_pgplistmtx`, `g_pgpcond` and `g_benchlistmtx` are no longer destroyed while
  other threads may use them.
- Each diagnostic is written with a single stdio call, so concurrent messages
  no longer interleave inside a line.

Results before and after the fix (8 cases that reach fatal() concurrently):

- **Before** (`cov-cli-race-before-20261021`): 19/80 repetitions ended by
  SIGSEGV or SIGBUS.
- **After** (`cov-cli-race-after-20261021`): 0/200 repetitions crashed, and
  every repetition exited with its documented status.

The regular suite also covers these paths:

- The 8 cases now require their exact status, and their profiles are merged.
- The `fix-fatal-race-*` group runs 6 repetitions of each in every run.

### 2. Temporary files (fixed)

- All temporary files that dtrace(1) creates use `tmp_mkstemp()`. This covers
  the `-E` base ELF and the `-E -e` inspection file, the received ELF and the
  derived guest ELF, the replay ELF and the `-Y` ELF. `tmp_mkstemp()` honours
  `TMPDIR`, except in set-id processes.
- Files are tracked until unlinked. fatal(), dfatal() and dabort() unlink every
  file still tracked. The `-E -e` file is untracked once its path is printed,
  because keeping it is the documented behavior.

Test coverage:

- Each case gets a private `TMPDIR`, and so does the guest run in host↔guest
  loops. After each case the runner fails it if any `dtrace-execprog.`,
  `dtrace-process-elf.`, `ddtrace-elf.` or `ddtrace-reemit.` file remains.
- The only exemption is the case that injects an `unlink()` failure.
- `fix-tmpdir-honoured` checks that the printed `-E -e` path is inside
  `TMPDIR`. This case fails before the fix.

/tmp before/after evidence (same 12 failure cases, `TMPDIR` left at `/tmp`):

- **Before** (`cov-cli-tmpleak-before-20261021/new-tmp-files.txt`): 9 files
  leaked.
- **After** (`cov-cli-tmpleak-after-20261021/new-tmp-files.txt`): 0 files leaked.

### Harness changes

- The fake daemon no longer gives script steps to a connection the consumer
  has closed.
- Frame-receive faults now target only large reads (`recv_large`). This removes
  their dependence on EAGAIN retries.
- `CLI_NO_TMPDIR` is used only for the /tmp evidence runs.
- Three extraction fixtures that compile regions of dtrace.c got stubs for the
  new helpers: `consumer-drain-receiver.c`, `consumer-stop-receiver.c` and
  `consumer-derived-replay.c`. The diff is
  `cov-cli-final6-20261021/harness-fixtures.diff`.
- All 11 extraction harnesses pass (`cov-cli-extraction-check3-20261021`).

## Follow-up (2026-10-21): `-x checkmodref` wired

Final evidence: `cov-cli-modref-final2-20261021`. 476/476 cases pass, the
historical baseline is merged, and the regression gate passes. Source diff:
`dtrace.c.checkmodref.diff` in that directory (dtrace.c sha256 `043ed758…`,
dtrace.1 `36cdbfa8…`).

- **Interface.** `-x checkmodref` is intercepted in dtrace.c's second option
  pass, like `resolvers` and `hypertrace_session_file`, and is never passed to
  libdtrace. It takes no value: `-x checkmodref=…` is rejected. It is valid
  only in the execution mode (including `-e`, `-E`, `-y`, `-Y`); `-l`, `-G`,
  `-h` and `-A` are rejected. Off by default.
- **Warning, not error.** The option scheme has no existing "make this fatal"
  convention, so none was invented.
- **Message.** `dtrace: ref-after-mod in provider:module:function:name:`
  followed by ` global`, ` thread`, ` clause`, ` external` or ` internal` for
  each kind the action references. The pre-existing `checkmodref()` callback
  gained only the `dtrace:` prefix used by other diagnostics. Documented in
  dtrace(1) under `-x`.
- **Where it runs.** Each program is checked exactly once, before it is
  enabled:
  - locally compiled programs in `exec_prog()` (normal execution and `-e` /
    `-E -e`);
  - in the `-E` host consumer, the program actually executed: received from
    dtraced, including guest-response flows, and checked in
    `execute_new_pgp()` before `process_new_pgp()`;
  - ELF programs (`-y`, `-Y`) in `link_elf()`.
  `checkmodref()` is no longer dead: dtrace.c now has 80/80 functions covered.
- **Tests (24).** For each kind: a program with one ref-after-mod (global,
  thread, clause, external via `exit` then `ustack`, internal via `speculate`).
  Also: a subroutine call (all five kinds), two reports from one clause,
  reference-before-modify, modify-only, references without any earlier
  modify, and option off. Usage errors: a value, an empty value, and the
  `-l`/`-h`/`-G`/`-A` modes. Execution continues after the warning; a received
  program in the host consumer is reported once; `-Y` and `-y` ELF programs.
  Expected text is derived from the modref rules documented in
  `analysis-modref.py`.

Coverage for dtrace.c is now 3141/3309 lines (94.92%), 1523/1745 branches
(87.28%) and 80/80 functions. HyperTrace-added code is 1571/1716 lines;
FreeBSD-origin code is 1570/1593 lines. The other two CLI files are unchanged.

**For the coordinator (libdtrace).** In the `-E` host flow, a received program
`dtrace:::BEGIN { x = 1; } dtrace:::END { trace(x); }` is rejected by
`dt_prog_verify()` with "typecast was not set to nop (!= 84)" and "failed to
verify DIF from host (0)". That happens before any check runs, so the
host-consumer test uses `exit(0); ustack();` instead. Also,
`host-stop-quiesce-deadline-expires` now waits for its `system()` child to
start before sending the stop.

**AGENTS.md.** This is a runtime option of the dtrace binary. No build inputs,
staging, signing or publication requirements changed, so
`/usr/src/usr.sbin/bsd-build/build-bsd.c` needs nothing (not edited).

**Process-control regression check (libdtrace/libproc/librtld_db changes of
2026-10-21 11:02–11:03).** The `cov-cli-modref-final2-20261021` run used those
libraries: its `libsnap/` copies, taken at 11:06, match the current shared
builds. All 12 `-c`/`-p` cases passed with unchanged expectations:
`proc-victim-exits`, `-exit-status`, `-killed`, `-quiet`,
`proc-grab-running`, `proc-create-and-interrupt`, `proc-create-empty-command`,
`proc-create-fails`, `proc-grab-invalid-pid`, `proc-grab-fails`,
`proc-argv-allocation-fails` and `grab-anonymous`. No exit-notification,
release or stop behavior changed.
