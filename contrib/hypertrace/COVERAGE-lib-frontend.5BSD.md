# libdtrace front-end coverage (group "frontend"), 2026-10-21

Scope: the D compiler front end in `cddl/contrib/opensolaris/lib/libdtrace/common/`:
dt_parser.c, dt_lex.l (generated dt_lex.c), dt_grammar.y (generated dt_grammar.c),
dt_decl.c, dt_ident.c, dt_cc.c, dt_cg.c, dt_as.c, dt_string.c, dt_module.c, dt_open.c,
dt_options.c, dt_provider.c, dt_xlator.c, dt_pragma.c, dt_inttab.c, dt_strtab.c,
dt_list.c, dt_regset.c. dt_resolver.c was added in round 3 for the errx() removal.

Everything was offline: no /dev/dtrace device, no kldload, no VM, no daemon. The kernel was modelled
with dtrace_vopen() vectors and preloaded shims (sysctl, kld, device open, ioctl, gethostname).

## Measurement

- **Before:** the coverage-library-verify3-20261021 profiles (library 24e075c6…), merged in
  `lib-frontend-20261021/m-base`.
- **After (rounds 1–4):** a stable snapshot of the instrumented tree, copied under the build lock
  to `lib-frontend-20261021/snap-final3` (libdtrace sha256 efb4778e…, identical at the start and
  end of the run).
  - The run covered every coverage-library-refresh suite, plus compiler-differential,
    disassembly-offline and all 18 frontend suites. Output: `lib-frontend-20261021/final-run3`.
  - **All 39 suites passed**, including:
    - ctf-linker-bounds, which failed on the round-3 snapshot and passes again after the typing
      agent's linker changes;
    - the strict frontend-codegen-link, with zero front-end/linker width disagreements.
  - Merged and exported in `lib-frontend-20261021/m-final3`, using only fresh profiles.
- The earlier measurements are kept for comparison: round 1 in `m-final`, round 3 in `m-final2`.
  So are the earlier copies of this record (`COVERAGE-round1.md`, `COVERAGE-round3.md`).
- Evidence root: `/usr/obj/5BSD-hypertrace-validation/lib-frontend-20261021/`. The subdirectories
  A/, B/ and C/ hold per-workstream runs, gap listings, failing-before evidence and `.orig`
  copies of the original sources.

| File | Lines before | Lines after | Branches before | Branches after | Functions before → after |
|---|---|---|---|---|---|
| dt_parser.c | 64.8 | 94.0 (3528/3752) | 56.9 | 91.1 (2098/2304) | 89/98 → 97/98 |
| dt_decl.c | 78.2 | 96.1 (692/720) | 66.8 | 92.7 (367/396) | 26/27 → 27/27 |
| dt_xlator.c | 69.0 | 95.6 (216/226) | 58.9 | 92.2 (83/90) | 5/8 → 7/8 |
| dt_pragma.c | 92.1 | **99.7** (339/340) | 80.1 | 96.3 (208/216) | 10/10 → 10/10 |
| dt_ident.c | 73.5 | 96.3 (626/650) | 51.0 | 93.5 (286/306) | 39/41 → 40/41 |
| dt_cc.c | 78.8 | **98.0** (1723/1759) | 72.9 | 95.0 (829/873) | 50/60 → 61/61 |
| dt_cg.c | 63.8 | 96.6 (1415/1465) | 57.9 | 88.9 (528/594) | 27/33 → 37/37 |
| dt_as.c | 55.8 | **98.7** (310/314) | 44.8 | 92.0 (162/176) | 8/10 → 10/10 |
| dt_regset.c | 88.5 | **100** | 64.7 | **100** (34/34) | 6/6 → 6/6 |
| dt_resolver.c | — | **100** (36/36) | — | 95.2 (20/21) | → 3/3 |
| dt_string.c | 25.4 | **100** | 25.3 | **100** | 5/6 → 6/6 |
| dt_list.c | 82.8 | **100** | 62.5 | **100** | 4/5 → 5/5 |
| dt_inttab.c | 92.7 | **100** | 75.0 | **100** | 5/5 → 5/5 |
| dt_strtab.c | 88.5 | **100** | 80.0 | **98.5** (67/68) | 11/11 → 11/11 |
| dt_options.c | 73.7 | **99.4** (701/705) | 73.5 | **99.2** (379/382) | 31/42 → 43/43 |
| dt_open.c | 60.9 | **98.2** (546/556) | 43.4 | **98.2** (278/283) | 6/11 → 11/11 |
| dt_provider.c | 63.6 | **100** (575/575) | 52.4 | 94.6 (263/278) | 18/21 → 22/22 |
| dt_module.c | 51.0 | **99.3** (1107/1115) | 41.2 | **98.7** (515/522) | 23/40 → 40/40 |
| **dt_lex.l, hand-written rules only**¹ | | **97.6** (570/584) | | 94.5 (259/274) | |
| **dt_grammar.y, hand-written rules only**¹ | | **99.2** (367/370) | | **100** (4/4) | |
| dt_lex.c (whole generated file, not counted) | 55.9 | 82.6 (1434/1736) | 54.6 | 76.4 (897/1174) | 15/38 → 21/29 |
| dt_grammar.c (whole generated file, not counted) | 72.6 | 94.6 (1216/1285) | 80.4 | 91.5 (441/482) | 2/2 → 3/3 |

Line counts changed: fixes added code, dead code and dominated checks were removed, and dt_lex.c
no longer generates flex's unused API.

¹ `A/tools/genmap.py` maps the generated files back to the .l/.y sources through `#line` and
drops the skeleton's `YY_BREAK`, `YY_RULE_SETUP` and `case N:` lines. Measured on library
a16e2bda (`A/m5-7`). Per the user's decision, the flex/yacc skeleton that libdtrace never enters
is not counted.

dt_resolver.c's single missing outcome is line 29, the false side of `yypcb->pcb_hdl != NULL`.
`dt_pcb_push()` sets `pcb_hdl` before it makes the pcb current, so that outcome cannot occur.

**Target status (>=97% lines and >=97% branches):**
- **Met on both metrics:** dt_string, dt_list, dt_inttab, dt_strtab, dt_options, dt_open,
  dt_module, dt_regset, and the hand-written dt_grammar.y rules.
- **Met on lines only:** dt_cc, dt_as, dt_resolver, dt_provider, dt_pragma, and the hand-written
  dt_lex.l rules.
- **Not met on either metric:** dt_parser, dt_decl, dt_ident, dt_cg, dt_xlator.

**Every remaining zero-count branch outcome is enumerated individually, by line:col, with a
reason.** Nothing is left unclassified. The lists, generated from llvm-cov export:
- `A/round4/dt_parser.c.waivers.txt` (169 outcomes), `dt_decl.c.waivers.txt` (27),
  `dt_xlator.c.waivers.txt` (7), `dt_pragma.c.waivers.txt` (8);
- `A/round4/dt_lex.l.rules.txt`, `dt_grammar.y.rules.txt`;
- `B/round4-branches.txt` (161 outcomes across dt_cg, dt_cc, dt_ident, dt_as and dt_resolver);
- dt_provider.c's assert proofs under "Round 4" below.

The summary of reasons is under "Remaining gaps".

## Suites added (round 1; see rounds 2 and 3 for frontend-parser-kernel and the new cases)

All suites are in `contrib/hypertrace/tests/`. Each takes `(new /usr/obj output dir, world dir)`,
i.e. the **world** argument kind.

| Suite | Cases | Oracle |
|---|---|---|
| frontend-parser-fold | 1716 | Random constant expressions. The system C compiler gives the value, sizeof and signedness; a C parse checks precedence. |
| frontend-parser-corpus | 675 | Accept/reject and diagnostic cases, each derived from a D-guide or compiler-source rule. A sysctl shim models the provider list. |
| frontend-parser-scoped | 108 | Scoped type names, with sizes and signedness from cc. Modules whose names contain '-' are synthetic loaded modules. |
| frontend-parser-printers | 27 | DTRACE_C_SUGAR output recompiled must give identical statements and DIF; tree dumps checked structurally. |
| frontend-parser-symbols | 31 | LP64/ILP32 shared objects built with ctfconvert/ctfmerge and registered as modules; symbol sizes checked against `nm -S`. |
| frontend-parser-oom | 10 sweeps | Every allocation in a front-end compile is failed in turn. It must give no crash and no silently different program. |
| frontend-codegen-arith | 2450 | DIF is executed in an interpreter written from the DIF ISA and compared with `cc -fwrapv` on value, width and signedness. |
| frontend-codegen-lang | 31 | D programs executed in the DIF interpreter against hand-derived values: variables, inlines, translators, arrays, strings, aggregations. |
| frontend-codegen-cc | 128 | Action encodings checked against sys/dtrace.h; relocations against nm; cpp, fcompile, libraries, register and table limits, joined printa format types. Runs with DTRACE_DEBUG_REGSET=1. |
| frontend-codegen-unit | 22 | Direct checks of dt_idhash, dt_regset, dt_idkind_name and compile_idents. |
| frontend-codegen-oom | 31 sweeps | Allocation failures targeted per function, located by DWARF address ranges. |
| frontend-runtime-utils | 5886 + 5920 fault | stresc2chr/strchr2esc compared with cc-compiled literals; dt_list, dt_inttab and dt_strtab against model data structures; D character constants. |
| frontend-runtime-options | 267 + 325 fault | Every option handler with valid and invalid values; DOF option import. |
| frontend-runtime-open | 53 + 6050 fault | Open flags and versions, vopen, device-model paths, close cleanup, the pid-unavailable message. |
| frontend-runtime-provider | 63 + 106 fault | Provider and probe creation, lookup, info and argument mapping through the modelled ioctl vector. |
| frontend-runtime-module | 341 + 343 fault | Synthetic ELF32/ELF64 modules and CTF checked against an independent Python ELF reader; symbol tie-breaks; address lookups. |

Shared helper files:
- frontend-parser.c, frontend_parser.py, frontend_parser_cases.py, frontend-parser-shim.c
- frontend-codegen.c, frontend_codegen_common.py, frontend-codegen-unit.c, frontend-codegen-oom-shim.c
- frontend-faults.h, frontend-runtime-shim.c, frontend-runtime-shim.h, frontend_runtime_common.py
- frontend-runtime-{utils,options,open,provider,module}.c

Edited outside the new suites, at the coordinator's request: one check in printf-conversions.c,
`case_printa_count_first`, which is now strict. The original is in `B/printf-conversions.c.before`.

## Bugs fixed (round 1)

Each fix has a regression test that failed before the fix. Failing-before evidence is in
`A/evidence/`, `B/<name>-before` and `C/fail-before/`.

**dt_parser.c**
1. Constant casts did not convert like the run-time cast: narrowing to a signed type, signed
   widening, and same-width signedness changes. `(char)200 < 0` folded to 0 and `(int)0x80000000`
   stayed positive. Fixed with the new `dt_int_convert()`.
   Tests: frontend-parser-fold; corpus `fold-cast-*`, `fold-cast-same-size-sign`.
2. A signed `>>` folded as a logical shift instead of an arithmetic one (`-8l >> 1` gave a huge
   positive value; now -4). Test: `fold-rsh-signed`.
3. A folded `!x` kept the operand's type instead of int. Test: `fold-lneg-type`.
4. `c ? a : b` with a constant condition skipped the usual arithmetic conversions
   (`sizeof(1 ? 1 : 2l)` was 4). Test: `fold-cond-promote`.
5. An uppercase `U` suffix was ignored when choosing an integer constant's type. Test:
   `int-hex-U-unsigned`.
6. A constant inline dropped its declared type: `inline unsigned char UC = 0x1ff` traced 511; it
   now traces 255. Tests: `inline-const-*`.
7. `?:` with a bottom-typed (foreign-target) operand crashed with a NULL pointer (SEGV). Test:
   `bot-cond`.
8. A compound assignment from a bottom-typed operand raised a false D_OP_VFPTR. Test: `bot-asgn`.
9. `dt_cook_xlator` overwrote attributes set by `#pragma D attributes ... translator`. Test:
   `attr-min-xlate`.
10. `dt_printd` (sugar output) printed constants, postfix operators, unary operators, casts, xlate
    and the probe target in forms that did not reparse to the same program. Test:
    frontend-parser-printers.
11. Under allocation failure, the TYPECAST name became "unknown" or empty, a silent miscompile. It
    now raises EDT_NOMEM. Test: frontend-parser-oom.

**dt_grammar.y**

12. `DUP()` could return NULL on allocation failure, which declarations read as "no type name". Test:
    frontend-parser-oom.

**dt_lex.l**

13. The predicate `/` lookahead compared flex's EOF with 0, so a predicate at the end of input was
    not recognised. Test: `pdesc-pred-no-body`.
14. End of input inside a comment or a control line was silently accepted. Tests:
    `eof-in-comment*`, `eof-in-control`.
15. Coordinator finding: scoped multi-word base types such as `` kernel`unsigned short `` did not
    parse; `` D`unsigned short `` silently became `unsigned`. Scoped tags (`` mod`struct x ``)
    are fixed too. Test: frontend-parser-scoped. pid-placement's check was flipped and confirmed
    live.
16. Coordinator finding: in type-name context only (DT_CTX_DTYPE), a module name may now contain
    '-', e.g. `` pid123`sshd-session`long ``. In program text, `a-b`, `x-1`, `a->b` and `` a-`sym ``
    are still subtraction. Test: frontend-parser-scoped.

**dt_decl.c**

17. A qualifier-only declaration (`const x;`) failed instead of meaning implicit int. Test:
    `decl-const-only`.
18. Defining an enum after a forward reference reported "type redeclared". Test:
    `decl-enum-forward-then-define`.

The earlier fixes are kept, and tests cover them: implicit enumerator value only without an
initializer, D_DECL_ENOFLOW at INT_MAX, and D_PDESC_ZERO printing the target only when it is
non-empty.

**dt_cg.c**

19. `dt_cg_typecast` did not convert same-width signedness changes:
    `(uint64_t)(unsigned)(int)-1` gave 0xffff…ffff instead of 0xffffffff. Test: arith; the folded
    and run-time results are compared.
20. `dt_cg_typecast` leaked a register on its early returns, so five scalar inline references gave
    D_NOREG. Test: `inline-noleak-*`.
21. Mixed signed/unsigned int comparisons, division and `?:` ignored the usual conversions (new
    `dt_cg_arith_convert`). Test: arith.
22. Dynamic args[] translator dereference and whole-struct expansion hit an assertion abort in
    `dt_regset_free(-1)`. Test: `xlate-dynamic-extern`.
23. Whole-struct translation kept the dynamic type, so the result had size 0. Tests:
    `translator-whole`, `typed-translated`.
24. In `dt_cg_inline`, a nested inline-array use (`f[f[x]]`) overwrote the outer parameter binding,
    giving a wrong register or a NULL dereference. Test: `inline-nested`.
25. Compiling a translator body leaked the input register and left the CGREG flag set (an upstream
    bug). Test: `xlate-dynamic-member-regs`.
26. Under allocation failure, the TYPECAST annotation was emitted with an "unknown" name. It now
    raises EDT_NOMEM. Test: frontend-codegen-oom.
27. `dt_cg_inline` could dereference NULL for anonymous inline parameters. Fixed defensively; no
    test reaches it.

**dt_cc.c**

28. A DTRACE_C_CTL compile returned an uninitialized program pointer. Test: `ctl-only`.
29. `dt_load_libs_dir`'s error check on the control-only pass was dead code, so allocation errors
    silently dropped libraries.
30. Coordinator finding: in a joined `printa("%@d %@d", @a, @b)`, every `%@` conversion was typed
    from the first aggregation. After count(), a negative sum printed as 18446744073709551611; it
    now prints -5.
    - Tests: `printa-joined-types` in frontend-codegen-cc, and printf-conversions'
      `printa-count-first`, now strict.
    - Evidence: `B/printa-before-*`, `B/printa-after-*`, `B/printa-strict-consumer`.

**dt_as.c**

31. `dt_copyvar` passed a NULL `di_object` to strncpy for a bottom-typed foreign-target variable,
    which crashed. Test: `zdefs-foreign-bottom`.
32. `dt_as_xlate` set `pcb_asxreflen` before its allocation succeeded, so `dt_pcb_pop` crashed after
    an allocation failure. Test: frontend-codegen-oom.

**dt_open.c**

33. Coordinator finding: a vector or NODEV handle left `dt_fterr` at 0, so pid probes reported
    "No error: 0". It is now ENODEV, giving "pid provider is not available: Operation not supported
    by device". ENODEV was chosen over an EDT_* code because dt_pid.c formats the value with
    strerror(). Test: `test_pid_unavailable` in frontend-runtime-open.
34. `dtrace_close()` dereferenced a NULL `dt_kmods` after that allocation failed during open. Test:
    the open fault sweep.
35. The printf-dictionary pointer types and the `immstack` typedef were not checked after creation.
    After an allocation failure the handle could not resolve `const char *`. Test: the ILP32 fault
    sweep.

**dt_module.c**

36. Several `dt_module_update` faults:
    - A partially loaded section-header table was accepted, and libelf later hit an assertion.
    - The alias strdup was unchecked, and the module was freed while aliases still pointed at it.
    - `sh_addralign == 0` gave wrong section addresses.
    - The section offset table was uninitialised.
    - A module with no `.data` claimed every higher address.

    Test: frontend-runtime-module, checked against an independent ELF reader.

**dt_provider.c**

37. `dt_probe_create`'s failure path read the compiler state while it was NULL, causing a SEGV
    during probe discovery. Test: the provider fault sweep.
38. `dt_probe_lookup` matched probes without the provider name, so it could return another
    provider's probe. Test: the probe-lookup checks.

**dt_options.c**

39. Option import from DOF had three faults: a DOF with no sections read an uninitialised pointer;
    another section's bytes were read as options; and an entry size of 0 looped forever. The
    section table is now bounds-checked. Test: `test_dofget`.
40. setenv/unsetenv matched variable names by prefix, so `FOOBAR` removed `FOO`. Test: "setenv
    FOOBAR keeps FOO".
41. The `core` option reported success after a failed atexit(). Test: "core retry after atexit
    failure".

**dt_string.c**

42. `stresc2chr` kept the backslash in `\'` and `\?`. Tests: cc-differential fixtures and D
    character constants in frontend-runtime-utils.

## Rounds 2 and 3: changes

### More bugs fixed

Each has a regression test that failed before the fix.

43. **dt_cg.c:** `huregs[0]`, `hargs[0]` and `hregs[]` crashed code generation with a SIGSEGV
    (`dt_cg_arglist`).
    - Cause: their ids (0x150–0x24f, 0x300–0x3ff) are above `DIF_VAR_ARRAY_MAX`, so they were
      treated as user associative arrays.
    - These ids cannot be encoded in `ldga`/`ldta`'s 8-bit field, so the arrays are now refused with
      `[D_IDENT_BADREF] … DIF has no encoding for array 0x302`.
    - Making them usable needs a new DIF encoding (kernel and verifier); that decision is left to
      the user.
    - Tests: `huregs-refused`, `hargs-refused` (frontend-codegen-cc). Evidence:
      `B/huregs-crash-before`.
44. **dt_cg.c `dt_cg()`:** every statement after the first leaked about 2.9 KB, because each
    DIFO's type-name table (`pcb_symtab`) replaced the previous one without freeing it.
    - Live bytes after compile and close, for 10 / 20 / 40 statements: 192856 / 221736 / 279496
      before the fix, 166864 for all three after.
    - LeakSanitizer is unsupported on this FreeBSD, so the test uses a live-allocation counting
      shim, `frontend-codegen-alloc-shim.c`.
    - Test: `compile-no-per-statement-leak` (frontend-codegen-unit). Evidence:
      `B/leak/evidence.txt`.
45. **dt_resolver.c:** gethostname or `kern.osrelease` failure called errx() and killed the process.
    The user approved removing process-terminating paths.
    - New `dt_resolve_fail()`: during a compile it raises a normal xyerror; otherwise
      `dt_resolve()` returns the new `DT_RESOLVE_ERROR` (dt_resolver.h) with errno set.
    - Also fixed: the sysctl call wrote 8 bytes past its stated length.
    - Tests: `resolver-{compile,direct}-{hostname,osrelease}` (frontend-codegen-unit), with
      `frontend-codegen-resolver-shim.c` making both lookups fail with EIO.
    - Evidence: `B/resolver-before/orig.out` (the original printed "failed to get hostname" and
      exited 1).
46. **dt_module.c `dt_module_load_proc`:** if the second pass found fewer CTF containers than the
    first, it left NULL slots, and `dtrace_lookup_by_type` then crashed in
    `ctf_lookup_by_name(NULL)`. A mismatch now fails the load with EDT_CANTLOAD.
    - Test: the process fault sweep in frontend-runtime-module.
    - Evidence: `C/fail-before/module-proc-ctf-slot-before-fix.txt`.
47. **dt_module.c:** after a failed process load, `dt_module_unload` cleared `dm_pid`, so the module
    permanently became a kernel module. `dm_pid` is now kept, so a later lookup retries.
    - Test: "process CTF after fault N" in the module sweep. No separate failing-before log was
      kept.
48. **dt_provider.c `dt_probe_desc`:** a glob matching several D-declared probes (all with id
    DTRACE_IDNONE) counted as one match, which skipped the documented stability rule. It now
    returns EDT_UNSTABLE.
    - Test: "glob matching two declared probes is unstable" (frontend-runtime-provider).
    - Evidence: `C/fail-before/provider-declared-glob-before-fix.log`.

Checked, not a bug: reading an undeclared `self->x` on a NODEV handle gives a normal D_VAR_UNDEF
diagnostic with no abort. Test: `self-undeclared` (frontend-codegen-cc).

### Dead code (classified first, as the user requires)

- **`dt_ident_builtin`** (dt_ident.c): a superseded leftover, **removed**.
  - It is not in FreeBSD. It arrived with the CADETS HyperTrace import (226a5912d89) and was
    already disabled there: its only caller was inside `#if 0` in `dt_ident_cook`.
  - It gated cooking for VM targets. That decision now lives in the cook and code-generation paths
    (`dt_resolve(ap->dn_target, 0)` in `dt_idcook_args`, and the target checks in dt_cg.c).
  - Removed with the `#if 0` block and the unused `dtp` local, after a whole-tree grep; upstream
    was not touched.
- **`dnwarn`** (dt_parser.c): a superseded leftover, the unused warning twin of `dnerror`. Nothing
  in the tree calls it, including the HyperTrace upstream overlay.
  - **Removed by the coordinator** in round 3. Its prototype was at dt_parser.h:291, which is outside this group. The removal
    is two lines: dt_parser.c:5592–5604 and dt_parser.h:291. 
- **`dt_node_is_builtin`** (dt_parser.c 3464–3493): an **unwired HyperTrace feature**, not a
  leftover. **Not wired; needs an owner.**
  - Its XXXDS comment says it was meant to mark builtins that carry guest pointers (e.g.
    `stringof(curthread->td_proc->p_comm)`) for audit.d.
  - As written it cannot be wired: the `strcmp(...) || strcmp(...)` chain is true for every name.
  - Proposed spec: true for a VAR node whose identifier is exactly one of execname, execargs,
    probeprov, probemod, probefunc, probename, zonename, arg0–arg9, fds or strjoin.
  - It needs a caller in the guest-memory typing path.

### Dominated defensive checks removed (user-approved)

Behaviour is identical in every case, and each was re-tested.

- **dt_as.c:** the `default:` of the first-pass relocation switch. `di_extern` is set only at
  dt_cg.c:124 (`dt_cg_xsetx`) and dt_cg.c:2024 (XLATE/XLARG), and is cleared at dt_cg.c:75.
- **dt_ident.c:** `argc == 1 ? " " : "s "` in two D_PROTO_LEN messages. Both sit inside
  `if (argc != 1)`. Test: `args-len-message`.
- **dt_cg.c:** `dt_node_is_arith(dnp) &&` in `dt_cg_signed_op`. Its only caller,
  `dt_cg_compare_signed`, returns early for non-arithmetic operands.
- **dt_module.c:**
  - The `dst` NULL checks in `dt_module_symgelf32/64`, and the `idp` checks in
    `dt_module_symname32/64` and `dt_module_symaddr32/64`. Their only callers, found by grepping
    the whole tree, are `dtrace_lookup_by_name` (passes `&sym` when the caller gives NULL, and
    `&id`) and `dtrace_lookup_by_addr` (called inside `symp != NULL`, passes `&id`).
  - The `idp != NULL` check on the "target" macro: dt_vopen inserts it or fails, before any module
    exists.
  - `&& dt_ddefs == NULL` in `dtrace_update`: dt_cdefs is created first.
  - The symtab/strtab section-load error checks, and `elf_getshdrnum() == -1`:
    `elf_getshdrstrndx` has already succeeded on the same Elf handle.
  - The link-map branch in `dt_module_load_proc_build` is now under `#ifdef illumos`, because
    `Plmid` is `(-1)` in libproc_compat.h:47.
- **dt_open.c:**
  - `&& p_providers != NULL`: the loop exits with `len > 0` only after a buffer is allocated.
  - `vector != NULL ||` in the supplied-descriptor check: only `dtrace_fdopen` passes a
    descriptor, and always with a NULL vector.
  - The `di_ops ?:` fallback: every `_dtrace_macros` entry has NULL di_ops.
- **dt_provider.c:**
  - The `*pp != NULL` loop guard and its assert in `dt_provider_destroy`: `dt_provider_create`
    always inserts the provider.
  - The `pv_probes != NULL` check: creation fails instead of leaving it NULL.
  - `nc == 0 &&` in `dt_probe_discover`: `xc == 0` implies `nc == 0`.
- **dt_options.c:** `opt == NULL ||` in `dt_opt_cpp_opts`. Its argument always comes from the
  `_dtrace_ctoptions` table.
- **dt_strtab.c:** `&& str_size != 0` in `dt_strtab_write`. The size starts at 1 and never
  decreases.

Fork A removed no checks in dt_parser.c, dt_decl.c, dt_xlator.c, dt_lex.l or dt_grammar.y. Each
candidate's proof depends on another file or on libctf's contract, so it is kept as a waiver below.

Round 2 also showed that several items listed as unreachable in round 1 are reachable; all are now
tested:
- D_FUNC_IDENT (`(1)()`);
- the *_AGGBAD diagnostics (`clear(@x[1])` on an unassigned aggregation);
- D_CG_DYN (a translated pointer used as a statement);
- the TYPECAST string-table overflow;
- the dt_parser.c 4362 cast.

### Tests added in rounds 2 and 3

- **New suite `frontend-parser-kernel`** (world argument), 4 cases. It redeclares the
  kernel-exported provider `test` against `dt_node_provider_cmp`'s rules: same probe accepted;
  added output prototype, different arity and unknown probe rejected.
- **frontend-parser-corpus**, now 723 cases. Added: ptrcompat swap, stack/immstack/sym/usym keys,
  multi-backquote scopes, foreign-target bottom DIF type, dt_decl prototype and array forms, empty
  enum completion, enumerator self-reference in C headers, and more.
- **frontend-parser-symbols**, now 32 cases, including an array of a module struct type.
- **frontend-codegen-cc**, now 162 cases. Added: AGGBAD, relocations with translator references,
  multiword register exhaustion (128 registers), the `version=1.5` translator binding, provider-
  declared args and xlate, and the huregs/hargs refusals.
- **frontend-codegen-unit**, now 27 checks: the leak and resolver regressions.
- **frontend-codegen-lang**, now 32 cases.
- **frontend-runtime-module:** tie-break objects in both symbol orders, `nosect`, small `.info`,
  NULL-symbol lookups and malformed pid modules.
- **frontend-runtime-open:** an unreadable provider list. The coordinator also removed the
  `dt_proc_init` fault skip, so all 6,050 allocations are now injected.
- **frontend-runtime-provider:** glob stability for D-declared probes.

## Round 4: changes

### Bugs fixed

Each has a regression test that failed before the fix.

49. **dt_parser.c, compound assignment:** `ptr += ptr` and `ptr -= ptr` passed the type check and
    then aborted the process at dt_cg.c:759 (`assert(dn_op == DT_TOK_SUB)`). A pointer may now only
    be adjusted by an integer (K&R A7.7); anything else gives D_OP_INCOMPAT.
    - Tests: corpus `add-eq-ptr-ptr`, `sub-eq-ptr-ptr`.
    - Evidence: `A/evidence/ptr-add-eq-abort-before`.
50. **dt_lex.l `dt_scoped_extend`:** with more than 255 blanks between the words of a scoped type,
    the word was dropped, so `` D`unsigned <300 blanks> short `` was typed as 4 bytes. Blank
    skipping is now unbounded (helpers `dt_scoped_word`/`dt_scoped_unword`).
    - Tests: `scoped-base-long-space`, `scoped-struct-long-space`.
    - Evidence: `A/evidence/scoped-long-space-before`.
51. **dt_cc.c `dt_preproc`:** the error path called `fclose(NULL)` when `tmpfile()` failed, which
    crashed. Found by the targeted `dt_preproc` OOM sweep.
    - Evidence: `B/preproc-fclose-crash-before`.

### Dominated checks removed (user-approved; behaviour identical)

- **dt_cg.c:1433, dt_cg.c:2094:** `|| dn_target[0] == '\0'`. **dt_ident.c:368:**
  `&& dn_target[0] != '\0'`. In both cases `dt_resolve()` already returns 0 for an empty target
  (dt_resolver.c, the `strlen(target) == 0` check comes first).
- **dt_cg.c `dt_cg_type_name`:** the `errno` check, the parent-container EAGAIN check and the
  empty-name check. `ctf_type_qlname()` records its allocation failure (EAGAIN, ctf_decl.c) on
  the container it was given, so the remaining test is `ctf_errno(dnp->dn_ctfp) == EAGAIN`.
- **dt_provider.c, two asserts that only repeat explicit code in the same function:**
  - `assert(*noffs < *maxoffs)` in `dt_probe_define`: the block just above doubles maxoffs when
    the two are equal.
  - `assert(pvp != NULL && prp != NULL)` in `dt_probe_info`: both NULL cases have already
    returned.

### Front-end / linker typing agreement

- **New suite `frontend-codegen-link`** (world argument). It compiles 812 expressions (operator ×
  type pairs, unary operators, ternaries, folded constants) and links each with
  `hypertrace_link()`.
- **Requirement:** the linker's result width must equal the front end's, and the recorded value
  must equal C's arithmetic taken at the front end's width.
- **Coordinator decision:** the front end is D's source of truth, so D's no-promotion semantics
  stay unchanged and the linker follows the front end.
- **Before the linker change:** 302 expressions disagreed (evidence `B/link-strict-before`), in
  four classes:
  - char/short arithmetic;
  - comparisons and `!`, typed 8 bytes;
  - unary operators and ternaries;
  - folded constants, typed by value through `promotedInteger`.
- **Literal constants:** fork A separately found the linker typing them by value: `(int)v + 1u`,
  `+ -1`, `+ 0xffffffff`, `+ sizeof (int)`. Evidence: `A/linktype/results.txt`.
- **After the typing agent's change:** on snap-final3 the suite passes with zero disagreements.
- frontend-parser-fold still agrees with cc on all 1716 expressions.

### Tests added in round 4

- **frontend-parser-corpus**, now 840 cases. Added:
  - every operator class with a bottom right operand;
  - D_DIV_ZERO for `%`, `%=` and `/=`;
  - enum and union keys;
  - forward pointers to different tags;
  - predicate retry;
  - long blanks and long tags in scoped names;
  - module names containing `-`, `_` and `.`;
  - `#line` and pragma malformations.
- **frontend-parser-symbols**, now 37 cases.
- **frontend-codegen-cc**, now 170 cases. A CTF-built offline module reaches USETX/ULOAD/UULOAD
  and symbol loads. Also added: preprocessor input through a pipe, fork failure under
  `RLIMIT_NPROC=0`, an interrupted wait, and an untruncatable CTF cache.
- **frontend-codegen-unit**, now 40 checks. Added the regset contract violations and the
  DTRACE_DEBUG_REGSET abort, each caught by a SIGABRT handler that calls exit() so the profile is
  written.
- **frontend-codegen-oom**, now 34 sweeps.

### dt_provider.c assert waivers (proofs)

These outcomes are counted only because the coverage build compiles asserts in (NDEBUG is off).
- **135:** `dtrace_close` takes the provider from its own `dt_provlist`, and `dt_provider_create`
  is the only inserter; it sets `pv_hdl = dtp`.
- **163:** the only caller, dt_parser.c:4885, passes `dx_id`, which is assigned
  `dt_xlatorid++` in dt_xlator.c.
- **256:** callers obtain `pvp` from `dt_provider_lookup` by strcmp of the same name. In
  `dt_probe_lookup` this relies on the kernel's PROBEMATCH contract for an exact provider name
  (kept).
- **257:** the `dt_probe_info` callers check `dtpd_id != DTRACE_IDNONE` explicitly. In
  `dt_probe_lookup` this relies on PROBEMATCH returning a real id (kept).
- **434–435:** both callers pass a freshly created DT_IDENT_PROBE identifier.
- **443–444:** `protoc < 2` arises only from the grammar rule without an output prototype, where
  `xargs` is NULL.
- **456:** probe identifier names come from `dt_probe_key` ("%s:%s:%s") or the parser's
  mod:func:name.
- **510–512:** `dt_probe_create` sets `di_data` and `pr_pvp = NULL`. Only `dt_probe_declare` sets
  `pr_pvp`, and D_PROV_PRDUP (dt_parser.c:4928) rejects a redeclaration.
- **568:** the only caller, dt_link.c:1770, passes a string-table pointer.
- **187 is unreachable:** a named output argument always matches an input argument.
  dt_decl.c:351–356 raises D_DECL_PROTO_FORM otherwise, using the same strcmp. Discovered probes
  have unnamed arguments.

## Issues in files outside this group (reported, not edited)

- **dt_proc.c:** the two defects below were fixed by the coordinator: the cleanup loop is now
  `while (i-- > 0)`, and `dt_proc_fini` has a NULL-environment guard. The dt_proc_init fault skip
  was removed (frontend-open-envfix-20261021).
- **dt_elf.cc:1808 `applyResolverFilter`:** treats any non-zero dt_resolve() result as "target
  doesn't match" and silently drops the statement. With the new `DT_RESOLVE_ERROR` it should report
  the error instead. Proposed patch: check for `DT_RESOLVE_ERROR` before the non-match path and
  propagate errno.
- **ctf-linker-bounds** failed on the round-3 snapshot (26dd22ef). It passes again on snap-final3,
  after the typing agent's linker changes.
- **`dnwarn`:** removed by the coordinator, together with its dt_parser.h prototype.
  `dt_node_is_builtin` is now commented as a future feature, with its broken condition noted.

- **dt_proc.c:**
  - `dt_proc_fini()` dereferences a NULL `dt_proc_env` when `dt_proc_init()` fails part way.
  - `dt_proc_init()`'s cleanup loop `while (--i != 0)` never frees entry 0.
  - Proposed fix: guard on `dt_proc_env != NULL` and use `while (i-- > 0)`. The fault sweeps skip
    allocations inside dt_proc_init because of this.
- **Kernel DIF emulator (`dtrace.c` CMP, also upstream):** it sets `cc_v = 0`, so signed branches
  are wrong when the subtraction overflows (e.g. `-2^63 <= 1000`). The test interpreter models the
  documented ISA.
- **libctf `ctf_add_member`:** D-declared structs get no tail padding (`struct { int a; char b; }`
  is 5 bytes; C gives 8). This is documented libctf behaviour, and the tests expect it.
- **libelf, libproc, librtld_db, libprocstat:** they abort or assert on allocation failure. The
  sweeps skip allocations inside these libraries.

## Divergences kept as D design (consistent between folding and run time)

- Intermediate values are 64-bit, so `0xffffffffu + 1 > 0`.
- There is no integer promotion for char/short operands, unary `+` or shifts.
- `'\xff'` is 255.
- `int (*p)[3]` parses as `int *p[3]` (an upstream grammar limitation).

The arith and fold suites record these in their divergence files rather than mismatching.

## Remaining gaps (waivers)

**Authoritative per-outcome lists (round 4).** These are generated from llvm-cov export on
snapshots taken under the build lock, and every zero-count branch outcome has a reason:
- `A/round4/*.waivers.txt` and `*.rules.txt`, generator `A/round4/classify.py`;
- `B/round4-branches.txt` (classes: assert, infeasible with its file:line proof chain,
  infeasible-table, infeasible-internal, infeasible-offline, infeasible-env, other-owner,
  not-recorded, race, contract);
- the dt_provider.c proofs above.

The line numbers in the summary below come from round 3. Where they differ, the round-4 lists
take precedence.

The five waivers that earlier rested only on "no program found" are resolved. Three are now
reached by tests and two are proved unreachable; none is left open. No production code changed.
- **dt_parser.c 302, proved unreachable.** libctf's `ctf_type_pointer` already retries with
  `ctf_type_resolve(type)` (ctf_types.c:677–684), and `base` is exactly that resolved type
  (dt_parser.c:295). So if the first call fails, the retry on `base` fails too.
- **dt_parser.c 4209, reached.** Tests `string-member-dot` and `string-member-arrow`: a struct
  member of D type `string` is kind ARRAY, but `dt_node_is_string` makes it an lvalue.
- **dt_parser.c 4378, proved unreachable.** A string-compatible operand is a char pointer, a char
  array or the D string type (dt_parser.c:1063–1087).
  - Char pointers and arrays satisfy `dt_node_is_pointer` (1101–1102), which the preceding
    operand of that arm accepts.
  - The D string type makes `ctf_type_compat` true at 4366, so an earlier arm is taken.
- **dt_lex.l B820:46, reached.** Test `scoped-base-formfeed`. The missing operand was `'\f'`, not
  `'\v'`; a form feed between the words of `` D`unsigned short `` now gives size 2.
- **dt_lex.l L974, reached.** Tests `tname-first-postdec` and `tname-first-postinc`. The earlier
  rules file was stale.

Updated figures (A/m5-8): dt_parser.c 2100/2304 = 91.1% branches; dt_lex.l rules 97.6% lines,
259/274 = 94.5% branches. frontend-parser-corpus passes 840 cases on library 126860a7.
`A/round4/dt_parser.c.waivers.txt` now lists 169 outcomes; `dt_lex.l.rules.txt` and
`dt_grammar.y.rules.txt` were regenerated.

Of dt_cg/dt_cc/dt_as's remaining outcomes, 63 are the failure arms of internal `assert()`s in
static functions; firing them would mean breaking the invariant. Six dt_ident.c outcomes are in
the typing agent's `dt_idhash_fill`/populate code.


The generated flex/yacc skeleton in dt_lex.c and dt_grammar.c is not counted: buffer stack,
NUL transitions, ECHO, `case 0` backup, yy_fatal_error, yacc error recovery, yyabort/yyaccept,
yygrowstack. libdtrace's own YY_INPUT and longjmp-based yyerror never enter it.

### dt_lex.l (hand-written rules)

- Allocation failures: 251, 294, 646–648, 838, 871, 901, 988.
- 725: `yybegin` is never called with the state already current.
- 749–750: the `default:` arm; every `yystate_t` has a case.
- 950: `id_or_type` runs only in S0.
- 969: `--` after a type name is counted with the `++` arm (`int32_t--` is tested).
- The partial branches are the same conditions, plus `i < 0` on a `[0-9]+` match.

### dt_grammar.y (hand-written rules)

- 232, 237, 238: the `d_expression` rules need DT_CTX_DEXPR, which no caller passes.

### dt_parser.c

**Dead code**
- `dt_node_is_builtin` 3464–3493 is an unwired feature (see above).
- `dnwarn`: removed by the coordinator.

**Unreachable**
- `opstr` 154–213: tokens that never become operator nodes.
- `dt_node_name` 479–559: those node kinds are Stable, or their operands fail D_ATTR_MIN first.
- `dt_printd`:
  - VAR/SYM/IF, 5156–5180 and 5288–5309: it only prints uncooked trees.
  - 5136, 5143, 5150: brace region artifacts.
- printr:
  - FREE, 5353–5355.
  - 5397–5399: named TYPE nodes exist only in declaration prototypes, which the printer never
    visits.
- `default:` arms: 3428, 4410, 5560–5562.
- 2493 D_DECL_USELESS: the inline rule requires a declarator name.
- 2674–2688: the grammar always passes a NULL decl.
- 2368: aggregations are not yet cooked there.
- 347 `<none>`: every NULL-container node is bottom, which is named one test earlier.
- 394, 419–426: `dt_type_promote` with two bottom operands, or a CTF encoding failure on corrupt
  CTF.
- 5634, 5668: `yypcb == NULL` happens only for consume-time warnings, which other suites cover.
- 5682, 5685: no `yyerror` call is made with yytext at a newline.

**Kept as waivers.** Each guard is dominated, but the proof crosses files or depends on libctf, so
it was not removed:
- 4098 D_OP_IDENT: dt_sugar.c:80 and :117 also build these nodes.
- 4271 D_IDENT_BADREF: dominated by the LBRAC prologue (3532–3562) plus `dt_xcook_ident` (2955).
- 3224: int64_t is defined in dt_open.c.
- 3264: libctf's `ctf_array_info` contract.
- 1119, 1155, 1161: `dt_node_is_void`, `_argcompat` and `_ptrcompat` are shared with dt_cc.c,
  dt_ident.c, dt_decl.c, dt_printf.c and dt_xlator.c.

**Allocation failures** (libctf-internal, or not reached by the targeted sweeps): 308, 314–316, 1425,
1685–1695, 1781, 1791, 1975, 2436, 2519, 3045, 3054, 3365, 4877.

**Environment**
- 845: an ILP32 pointer without the userland flag; only a 32-bit process supplies one, and ILP32
  kernel modules get D_SYM_MODEL (tested).
- 902: a symbol-size lookup failing right after a successful lookup.
- 942: float encoding needs kernel CTF.
- 1306: a function-typed key, i.e. a kernel function symbol used as an index.
- 1870, 3082 D_ID_OFLOW: needs about 2^16 variables.

**Now enumerated:** in round 4, `A/round4/dt_parser.c.waivers.txt` lists all 170 remaining
outcomes individually.

### dt_decl.c

**Unreachable**
- 130:39, 186:39, 536:39: an UNKNOWN-kind decl never has a name.
- 170:21: `dt_decl_top()` longjmps instead of returning NULL.
- 254:30: the kind is set only together with a name.
- 328:34: no caller passes `DT_DP_DYNAMIC`.
- 336:13: prototype parameters are never bottom-typed.
- 871:6: `dd_ctfp` is always a registered module's CTF.
- 1041: `default:` arm.

**Kept as waivers** (cross-file contracts)
- 183, 200, 208, 527, 530, 533, 727, 1147: guaranteed by the grammar.
- 248–249: `id_or_type` (dt_lex.l) returns IDENT once a type is set.
- 1114: `dt_pcb_pop` (dt_pcb.c:117) pops nested scopes first.

**libctf failures:** 596 (`ctf_type_encoding` on a type just confirmed INTEGER), 641–642 and 970–971
(`ctf_add_type_cp`/`ctf_update` allocation), and the failure side of 953.

### dt_xlator.c

- 55, 61, 93, 215: allocation failures during dynamic member creation.
- 283: needs a type that `ctf_type_resolve` cannot resolve; no front-end path makes one.
- 325–326: pass 2 is redundant only because libctf's `ctf_type_compat` resolves typedefs (kept as
  a waiver).
- 365–368 `dt_xlator_lookup_id`: reached only by provider DOF export of translator references,
  which needs a program linked with USDT probe sites (dtrace -G). The suite asserts "No probe sites
  found". Better covered from linker-corpus.

### dt_pragma.c

- 203: allocation failure.

### dt_ident.c

- 206–218, 300–318: parsing of the static builtin prototype table; every entry is well formed.
- 368:43: depends on `dt_resolve` with VM targets.
- 486: `uint64_t` is always present.
- 527:30, 560: parser and dt_open.c invariants.
- 599: no caller.
- 872, 885, 973: the delete-chain end, orphan delete and NULL-name creation cannot happen with the
  current callers.
- 1062, 1064–1066: inline roots of kind SYM (needs CTF), AGG (an aggregation cannot be named in an
  inline), INLINE or PROBE.
- 669–691, 783, 824: the typing agent's new `dt_idhash_fill` code. The open-time NULL-pcb longjmp in
  `dt_idhash_populate` belongs to that agent.

### dt_cg.c

- **Cross-container or kernel CTF:** 89, 102, 242, 385, 1242, 2155.
- **Internal errors:** 198, 286, 391, 456 (bit-field encoding), 203 (load size), 486, 1621 (store
  size), 2341, 2371 (node or token kind).
- **Copied or kernel types:** 139, 142, 222 (USETX/UULOAD), 2103.
- 513, 518–520: allocation sub-conditions of the libctf type-name fallback.
- 672: a by-reference value of size 0 cannot exist.
- 941, 964: a right-only string operand fails the parser's type check first.
- 1437, 2098: need registered VM targets.
- 1446: LDTA; there are no thread-local built-in arrays.
- 1530, 1545: the grammar rejects anonymous inline parameters.
- 2012: XLATE with `dx_arg == -1`; guards dt_xlator.c's contract (kept).
- 2259 D_CG_EXPR: DT_CTX_DEXPR has no caller.
- 2321, 2332: kernel symbols with CTF.

### dt_cc.c

- 525:61: the scratch format cannot be shorter than the same string parsed twice.
- 779, 793: print() of a pid module.
- 1264, 1738, 1741: internal errors.
- 1882: every cvar is version 1.0.
- 1927:38: `dx_ptrid`'s version is always copied from `dx_souid`'s.
- 1968, 1979, 2037, 2044, 2058:
  - cpp tmpfile, malloc or fork failure;
  - tty input;
  - EINTR;
  - the post-fork child, whose lines run after exec and are not recorded.
- 2109: a library path without "/" (kept: dt_pragma.c also calls it).
- 2196: allocation failure in a nested sort level.
- 2419: a race between the library passes.
- 2661: DT_CTX_DEXPR.
- 2684–2691: CTF cache write failure; devfs accepts ftruncate and lseek.
- 2749: allocation failure outside any compilation.

### dt_as.c

- 300: invalid link mode; dt_options.c validates linkmode (kept).
- 352, 464: XLATE opcode, as for dt_cg.c 2012.

### dt_regset.c

- 91: the deliberate abort() under DTRACE_DEBUG_REGSET; an aborting child does not flush its
  profile.
- 48–56 and the remaining allocation-loop outcomes: calloc failure inside `dt_regset_create` at
  open.

### dt_module.c

- 571, 1242: `gelf_getshdr()` on a section libelf just iterated.
- 657: libproc paths are absolute.
- 1079: needs 2^32 externs.
- 1181:44: fstat64 failing after a successful open.
- 1201:29: `elf_cntl(ELF_C_FDREAD)` failing on a readable file.
- 1218: the unknown-ELF-class default; libelf rejects it earlier.

### dt_open.c

- 950/951: rd_init succeeds at RD_VERSION on the first try.
- 1034: `while (1)`.
- 1209: elf_version cannot return EV_NONE.
- 1616: ctf_import between same-model containers.
- 1703: types inserted just before.

### dt_options.c

- 852, 860: the string type is always dt_open's char array. Kept, because the proof depends on
  libctf internals.

### dt_provider.c

- 187: the parser rejects that mapping first.
- 15 assert expansions that hold: 135, 163, 256, 257, 434, 435, 443, 444, 456, 510–512, 568, 632,
  844.

### dt_strtab.c

- 71: `assert(bufsz != 0)` holds.

### dt_resolver.c

- 29 false outcome: `dt_pcb_push` sets `pcb_hdl` before making the pcb current.
