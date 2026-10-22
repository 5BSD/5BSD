# libdtrace typing-group coverage (2026-10-21)

Scope: the HyperTrace type checker, linker and ELF serializer in
`cddl/contrib/opensolaris/lib/libdtrace/common/`: `dt_typing.cc`,
`dt_typing_var.cc`, `dt_typing_helpers.cc`, `dt_typing_reg.cc`,
`dt_typing_subr.cc`, `dt_typefile.cc`, `dt_dfg.cc`,
`dt_hypertrace_linker.cc`, `dt_elf.cc` and their headers, plus `dt_error.c`
(the program-error path; moved to this group mid-task).  All testing is
offline: no daemon, no `/dev/dtrace`, no VM, no kldload, install or reboot.
The kernel's module inventory is answered by a `kldnext`/`kldstat` interposer
over CTF fixtures built with `cc -g` and `ctfconvert`.  dtraced is a fake
server on a socket under the case's `TMPDIR`, reached through a `connect()`
interposer.

## Measurement

LLVM source coverage on the instrumented `libdtrace.so.2`
(`coverage-compiler-20261020`), built under the shared build lock.  The
merged profile contains fresh profiles only, from:

- `typing-inference` and `elf-coverage-matrix` (this group's suites);
- the existing suites that reach the linker: `linker-corpus`,
  `linker-offline`, `ctf-linker-bounds` and `program-verify-mutation`.

Final run (round 3): library sha256
`f3953208503a7954122ec61d17ef40e01104e5655cb1b904edf118e55b4314a4`
(unchanged across the run).  Every suite exited 0: `typing-inference` (646
cases in 16 harness runs), `elf-coverage-matrix`, `linker-corpus`,
`linker-offline`, `ctf-linker-bounds`, `program-verify-mutation`,
`program-properties` (120 cases), `frontend-runtime-options` and
`coverage-cli` (477/477).  Evidence is in
`/usr/obj/5BSD-hypertrace-validation/lib-typing-20261021/`:

- `ls-r4/` holds the suite outputs;
- `elfm-m/` holds the ELF matrix;
- `pp-f/`, `fe-e/` and `cli-m/` hold program-properties,
  frontend-runtime-options and coverage-cli;
- `cov-r5/` holds the merged profile and per-file `llvm-cov show`
  output.

"Before" counts lines and branches from the session's baseline
(`lib-typing-20261021/baseline/`, the whole-library refresh at the start).
They use `llvm-cov show` line and branch counts, so their denominators differ
slightly from the `report` totals after.

## Per-file results

| File | Lines before | Lines after | Branches before | Branches after |
|---|---|---|---|---|
| dt_typing.cc | 37.9 | 99.47 (1326/1333) | 46.1 | 98.47 (644/654) |
| dt_typing_subr.cc | 58.8 | 99.13 (683/689) | 59.2 | 98.80 (413/418) |
| dt_typing_var.cc | 32.8 | 100.00 (494/494) | 37.2 | 99.05 (208/210) |
| dt_typing_helpers.cc | 34.7 | 99.31 (288/290) | 28.9 | 97.50 (195/200) |
| dt_typing_reg.cc | 38.2 | 100.00 (116/116) | 47.8 | 100.00 (68/68) |
| dt_typing.hh | 60.0 | 100.00 (9/9) | 0.0 | 100.00 (12/12) |
| dt_typing_var.hh | 0.0 | 100.00 (6/6) | – | – |
| dt_typefile.cc | 67.6 | 100.00 (311/311) | 54.5 | 97.86 (137/140) |
| dt_dfg.cc | 85.3 | 99.65 (562/564) | 75.9 | 98.88 (532/538) |
| dt_hypertrace_linker.cc | 78.7 | 99.29 (702/707) | 73.3 | 97.12 (439/452) |
| dt_elf.cc | 72.5 | 98.62 (2283/2315) | 72.9 | 98.16 (960/978) |
| dt_elf.hh | 100 | 100.00 (23/23) | 100 | 100.00 (2/2) |
| dt_elf_bounds.hh | 100 | 100.00 (15/15) | 62.9 | 85.00 (17/20; the rest waived, below) |

**Status (round 3).** Every file of the group meets 97% for lines and
branches except `dt_elf_bounds.hh` (85% branches), whose three remaining
outcomes are infeasible (waivers below).  The typing.hh figure counts the
library's copy of `varEqualCTF` (an inline function: the harness's own copy
is not the library's).

**Not in this group.** `dt_typing_stack.cc` (66.7/74.1) was edited only to
propagate program errors and to make its variable stacks per-link (see
below).  Its open defect is reported to its owner.

## Suites

Each suite takes a new `/usr/obj` output directory and the matched object
tree (the "world" path).  It refuses an existing output directory, writes
`results.json` and `provenance.json`, prints `PASS:` or the failures, and
exits nonzero on failure.

| Suite | Argument kind | What it checks |
|---|---|---|
| `contrib/hypertrace/tests/typing-inference.py` | world | Builds CTF fixtures and the kld shim, then runs the harnesses in the next table (some under several module inventories). |
| `contrib/hypertrace/tests/elf-coverage-matrix.py` | world | ELF round trips and malformed files, decoded independently with `readelf`, with writer fault injection (`elf-coverage-matrix.c`, `elf-fault-shim.c`, `elf-fault-new.cc`). |

`typing-inference.py` runs these harnesses:

| Harness | What it checks | Oracle |
|---|---|---|
| `typing-inference` | Compiled D corpus | Per-instruction oracle from DIF semantics and the D ident table. |
| `typing-units` | Type comparison, definitions, type files and the DFG | libctf and DIF semantics. |
| `typing-rules` | ~160 rules of `inferNode()` | The prototypes in `dt_open.c`, checked at every subroutine argument position. |
| `typing-reject` | Malformed DIFOs, statements, branches and relocations | – |
| `typing-args` | Probe argument typing | dtrace(4) model through `dtrace_vopen` (mocked ioctls). |
| `typing-kernelenv` | Type checking under unusual module inventories | Run with min, illumos, none, kldfail and missing inventories. |
| `typing-progerr` | Program errors returned, not fatal | – |
| `typing-roundtrip` | compile → guest ELF → link → host ELF → `dt_prog_verify` | The compiler's own `dtrace_diftype_t` values. |
| `typing-casts` | Integer casts and arithmetic after linking, run by a DIF interpreter written in the test | C itself (1472 evaluations: 16 types, boundary values). |
| `typing-vprog` | The guest forwarding program (`dtrace_vprog_from`) | The source program's probes, clauses and argument use. |

## The program-error rework (approved by the user)

Before this rework, `dt_set_progerr()` ended the process: it called
`errx(1)` for host consumers, and did the same on guests after forwarding the
program.  A library caller therefore lost its process on an ill-typed
program.  Now:

- **Recording.** `dt_set_progerr()` (dt_error.c) records the error
  (`dp_haserror`, `dp_err`), prints the recorded text, and returns.
- **Guest forwarding.** A guest forwards the erroneous program to dtraced.
  Each forwarding failure is appended to `dp_err` and returned as -1:
  open_dtraced, the temporary file name, mkstemp, ELF creation, fsync,
  lseek and send.  The temporary file is always removed; previously it was
  leaked when the send failed.  A message filling `dp_err` is cut short with
  "..." so that the reason still fits.  When formatting fails, the fallback
  text is printed (previously an empty line).
- **Program errors in the type checker and linker.**
  `HyperTraceLinker::progErr` and `TypeInference::progErr` are the only
  callers.  Every one of the ~106 call sites returns failure:
  - `argCmpWith`, `setBuiltinType` and `setTypeFrom` now return status;
  - `inferNode()` stops after a definition check records an error;
  - `inferDIFO()` stops on any recorded error, as a safety net.

  `hypertrace_link()` returns `E_HYPERTRACE_TYPING`, or `E_HYPERTRACE_SYS`
  when a guest could not forward; an assertion states that every program
  error fails the link.  Only the first error is the program's (recorded and
  forwarded once); later ones are only printed.
- **Other process exits reachable from bad input**, now returned errors:
  - `computeBasicBlocks()` called `errx` on branch labels outside the code
    and on a branch as the last instruction.  `checkDIFO()` now rejects both
    (`E_HYPERTRACE_LINKING`) and the old site is an assertion.
  - `dt_typefile_openall()` called `errx` when `kldstat` failed.  It now
    returns -1, and the link fails with `E_HYPERTRACE_SYS` and the message
    "kldstat() failed with: …".
  - `dt_idhash_populate()` (dt_ident.c) longjmp'd through `yypcb`, which is
    NULL outside a compilation.  Outside a compilation it now returns NULL
    with `ENOMEM`; the remaining template stays pending and the next use
    resumes.  Inside a compilation it unwinds as before.  `dt_idhash_iter()`
    (also reached from `dt_pcb_pop()` during unwinding) never unwinds.
- **dtrace(1).** `link_failed()` in `dtrace.c` reports a program error
  exactly as before: the library's line, then `dtrace: <message>`, exit 1.
  `coverage-cli.py` passes 477/477, including the new case
  `exec-program-type-error`.  Its dtrace.c denominators were re-reviewed to
  3315/1747/81 (`cli-g/`).  Run concurrently with other heavy suites,
  `cli-e/` timed out in signal-driven cases; alone it passes.
- **Fail-before evidence.**
  - `progerr-before.log`: all five `typing-progerr` cases end with exit 1.
    The not-acknowledged guest case left
    `/tmp/ddtrace-set-prog-err.mcob4iN` behind, which was recorded and then
    removed.
  - `idh-before/`: the idhash case dies with SIGSEGV.

## Bugs fixed, with regression tests

Test names are `harness:case`.

**Type checker**

| Bug | Regression |
|---|---|
| `dtdt_ckind` held a truncated CTF type id, not a CTF kind (return types and variable types), so the verifier rejected correctly linked programs on the host round trip (consumer agent's diagnosis, `lib-consumer-20261021/D-regressions/typecast-diagnosis.txt`). It now holds the kind of the resolved type; D strings get `CTF_K_UNKNOWN`. Readers checked: the verifier compares against `dt_node_diftype()` kinds; `dt_dis.c` prints a kind; ELF copies the struct; the kernel does not read it. | `typing-units:ret-rtype-by-action` (libctf kind oracle; lwpid_t's id ≠ its kind), `typing-roundtrip:*` |
| A store of a string (`s = execname`) returns nothing, but its void return type was marked by reference with kind 0xff, so the round trip failed verification. | `typing-units:ret-rtype-values`, `typing-roundtrip:roundtrip-string-variable` (fail-before `rt-dump.log`) |
| A dereferenced userland struct got an 8-byte record (the pointer's size), and `*(userland string *)p` became an 8-byte CTF pointer. By-reference returns are now described by the object (size and kind, `BYUREF` included), and a userland D string stays a string by user reference. | `typing-roundtrip:link-matches-compiler-return-types`, `roundtrip-userland-*` |
| Struct copies into by-reference variables were rejected: `this->s = *(struct s *)p` and `self->t = *curthread` gave "type mismatch in variable store". The member relocation through such a variable failed too. | `typing-roundtrip:struct-copied-into-clause-variable` |
| A member found by offset was looked up again by name. Every anonymous member is named "", so byte 16 of a struct with two anonymous unions resolved to the first. | `typing-rules:add-struct-second-anonymous-member` (fail-before `anon-before.log`) |

**Process-global state and leaks**

| Bug | Regression |
|---|---|
| Process-global state: the variable stacks (`var_nodevecs`, dt_typing_stack.cc) grew with every link and kept pointers to finished links' nodes. Type files outlived their link, which matters when a later link runs on another handle after `dtrace_close()`. Now the stacks belong to the link and type files are released after it. | `typing-progerr:type-files-released-after-link`, `valid-links-repeated-without-leaks` |
| `dtdo_types` (per-instruction type names) were never freed, and were leaked again on relink. `dt_difo_dup()` copied the pointer, which would double free. They are now freed in `dt_difo_free()`, and a dup does not share them. | `typing-progerr:valid-links-repeated-without-leaks` (0 bytes per link after subtracting compile growth; an allocation tracker showed 0 surviving blocks over 58 links) |

**Program-error path**

| Bug | Regression |
|---|---|
| Program errors ended the process (rework above). | `typing-progerr:error-returned-and-process-continues`, `errors-repeated-without-leaks`, `guest-*`, `typing-kernelenv:kldfail-link`, `typing-reject:dfo-branch-*`, `typing-rules:ctor-every-type-name-and-link`, `coverage-cli:exec-program-type-error` |
| The guest forwarded once per program error. | `typing-progerr:guest-forwards-once-for-several-errors` |
| An unformattable error printed an empty line; a full `dp_err` lost the forwarding reason. | `typing-progerr:unformattable-error-is-printed`, `long-error-keeps-forwarding-reason` |
| idhash longjmp through a NULL pcb. | `typing-progerr:idhash-population-failure-outside-compilation` |

**Verifier** (dt_program.c, approved)

| Bug | Regression |
|---|---|
| For a BOTTOM-typed base, a CTF result's kind must now fit how the value is returned: a register value is an integer, enum, float or pointer; a by-reference value is an array, struct or union. A type id passed off as a kind is rejected. | `program-verify-mutation` bottom-rtype mutants `ctf-enum`, `ctf-float`, `ctf-struct-byref`, `ctf-union-byref`, `ctf-struct-byvalue`, `ctf-type-id-as-kind`, `ctf-integer-byref`, `ctf-pointer-byref` |

**Fixed earlier in the task, before the rework** (regressions in
`typing-units`, `typing-rules`, `typing-reject` and `typing-inference`):

- `dt_typing.cc`:
  - an STX type name was compared with the wrong buffer;
  - LDLS/LDTS called `strcmp(NULL, NULL)`;
  - a userland temporary buffer leaked;
  - a variable's symbol from another DIFO was used, so
    `BEGIN { self->p = &curthread->td_tid; } END { trace(self->p); }` failed;
  - `dt_setx_value` truncated values to int;
  - TYPECAST/USETX symbols were not bounds checked.
- `dt_typing_helpers.cc`: `ctfTypeCompare` used uninitialized ids, compared
  members across containers and asserted on floats.
- `dt_typing_subr.cc`: INDEX/RINDEX checked arg0 where arg1 was meant;
  there was no arity check; 47 `assert(argN->tf)` could fire on bad input.
- `dt_typefile.cc`:
  - `getMembInfo` looked up uninitialized memory;
  - Typefile objects went stale across handles;
  - `buildStruct` results were not cached.
- `dt_dfg.cc`:
  - loads took their address from the wrong field (RS, not R1);
  - ALLOCS took its size from R2, not R1;
  - the active-register array was undersized.
- `dt_hypertrace_linker.cc`:
  - DIFO shape validation was added (`checkDIFO`);
  - a stale inthash was reused;
  - the scope was not validated during assembly.
- `dt_elf.cc`, seven bugs:
  - the writer ignored `createElfActions` errors;
  - the "no-last" format crashed;
  - a second create produced an unreadable file (`dtad_elfact`);
  - section buffers leaked;
  - the `BEGIN {}` round trip failed;
  - the getshdr NULL check tested the wrong variable;
  - the dirty flag and `setErrorMessage` were wrong.

## Simplifications (approved: provably redundant checks)

- `dt_typing.cc`:
  - D intrinsic types (`int8_t` … `uint64_t`, present in every D container)
    are set without a failure branch; any failure would still be a recorded
    program error that ends `inferDIFO()`;
  - `findMemberOffset` takes the member's type and offset from the libctf
    iteration (this also fixed the anonymous-member bug).
- `dt_typing_helpers.cc`: the tail of `typeCompare` (every other class an
  integer can meet is handled above it); a dead assertion after the
  both-bottom check.
- `dt_typing_reg.cc`: `onode == nullptr` (the first iteration sees its own
  definition).
- `dt_typing_var.cc`:
  - a dead fallback after the variable-not-found error (LDLS/LDTS);
  - `setBuiltinType` paths that continued after a report.
- `dt_dfg.cc`: `usiteContainsVar` is now a table of (id, scope, kind);
  `usiteContainsReg` returns early for non-clobbering calls instead of
  testing `check &&` ten times.
- `dt_typefile.cc`: the D/C container lookups in `openall` are assertions,
  because `dtrace_open()` creates both.
- `dt_typing_stack.cc`: a dead NULL check on a freshly made stack.
- `dt_error.c`: a reason-length cap (reasons are at most 255 bytes).

Uncalled functions (round 2, the user's decision): see "Dead functions"
below.

## Gaps (with reasons): every remaining outcome is a waiver

**`dt_typing_helpers.cc`** (5 outcomes):
- `dt_get_class`'s self-reference guard (`id == ot`): only a typedef of
  itself reaches it, and libctf refuses to create one
  (`ctf_add_typedef()` checks that the target exists); a corrupt CTF
  section would be needed.
- Four assertion failures (the C++ assertions in this file count their
  failing outcome): `ctfTypeCompare`'s two "both type files given" asserts and
  `typeCompare`'s two "no NONE operand" asserts, invariants of their
  callers.

**`dt_typefile.cc`** (3 outcomes), all in the forward-resolution loop of
`getMembInfo`: `ctf_type_name()` failing for a valid forward id; the
lookup by name failing (it finds at least the forward itself, in its own
module); and the lookup returning another type of the same container (a C
translation unit cannot hold a forward and a definition of one name as two
types).

**`dt_elf_bounds.hh`** (3 outcomes): misalignment (libelf copies every
section's data into a buffer of its own, `elf_getdata()`, so `d_buf` is
always aligned: a section at an odd file offset was tried and is copied);
`elfArrayFits()` with a zero width or a header larger than the data (every
caller passes a constant non-zero width, and a header already bounded by
`elfBoundedRecord()` or the loop guard).

**`dt_hypertrace_linker.cc`** (13 outcomes): allocation and libdtrace
failures (`dt_inttab` insert, a return size above `UINT32_MAX`, a non-zero
encoding offset, processDIFO error propagation reached only through
allocation faults).

Simplifications in round 3 (infeasible libctf failures): the `getReference()`
failures inside `stripReference`/`stripTypedef` and `getArrayInfo()` of an
array are assertions now (`dt_typefile.cc`); `buildStruct()` of a
structure is no longer checked in `ctfTypeCompare` and
`getSubtypeRelation`, nor `getArrayInfo()` in `dt_get_class` (comments
state why).  `dt_get_class` takes any class a forward's definition has
(it took only structures and integers).

## BOTTOM-typed return types (analysis)

A host DIFO whose return type is `DIF_TYPE_BOTTOM` names guest data.  The
guest's linker resolves it from guest CTF that the host does not have, so the
host cannot recompute the type or size.

**What `dt_prog_bottom_rtype_ok()` checks now.** This is the consumer
agent's tightening plus this group's kind rule:

- the result is BOTTOM, CTF or STRING;
- BOTTOM is unchanged, apart from the `CTF_BOTTOM_TYPE` marker;
- STRING adds only `DIF_TF_BYREF`;
- CTF is either `dt_void_rtype`/`dt_int_rtype`, or keeps the compiled flags
  (optionally plus `BYREF`) with:
  - a register-sized by-value size, or a non-zero by-reference size;
  - a CTF kind matching the return mode: integer, enum, float or pointer by
    value; array, struct or union by reference.

The kind rule became meaningful only once `dtdt_ckind` holds a kind (fixed
above).

**What remains a guest assertion.** Which kind it is, and the by-reference
size.  `program-verify-mutation` classifies these as "known gap:
BOTTOM-typed DIFO return type" (9 mutants in program 5).

**Closing the gap.** It would need either guest CTF on the host, or a typed
size bound per action (for example, the buffer the consumer will read for a
by-reference record).  That is a design decision, not a test change.

## Round 2 (correctness fixes requested by the coordinator)

Each fix has a regression; "before" evidence is the pre-fix library's
output recorded in `lib-typing-20261021/`.

**Casts kept their conversion code (`dt_hypertrace_linker.cc`).** The linker
turned the compiler's sll/sra pair before a TYPECAST into nops, so
`(char)arg0 + 1` saw all 64 bits of arg0 (`casts.log`: the pre-fix DIF, with
nops and a 1-byte record).  The code the compiler emits is the cast itself
and now stays; the look-back (and `checkSETXDefs`/`patchSETXInstructions`)
is gone, and a leading TYPECAST's symbol is checked like any other
(`ctf-linker-bounds` updated: its old expectation pinned the skip that only
existed for the look-back; this is the ctf-linker-bounds failure the
coordinator saw).  With it, the type checker gives integer arithmetic C's
type (integer promotions and usual arithmetic conversions, LP64; a shift
has its promoted left operand's type; a constant has C's constant type by
value), so `(char)arg0 + 1` is an int with a 4-byte record, as the compiler
says.  Regression: `typing-casts:integer-casts-match-c` (every width and
signedness; values 0, 0x7f, 0x80, 0xff, 0x100, ..., negatives, INT64_MIN/MAX;
`(T)arg0`, `+ 1`, `* 2`, `- 0x7fffffff`; record size and value against C),
`cast-of-cast-and-shift`, `typing-rules:arith-int-int-c-conversions` and
`arith-int-and-constant` (C's `decltype` as the oracle).  The inference
oracle (`typing-oracle.h`) models the same rules independently.

**One hypercall per guest firing (`dt_program.c`).** `dtrace_vprog_from()`
made one forwarding statement, so one hypercall, per source statement (one
per action); a hypercall names only the probe and the host runs every clause
on the vprobe for each, so each host action and predicate ran N times per
firing.  Each statement's DIFO also loaded only the stack arguments of the
actions seen before it was built.  Now all statements of a probe are
collected first and one forwarding statement per probe is emitted (first
appearance order), with every argument any clause reads, the largest
stack() frame count, the time references, and one immstack() capture (the
guest captures the firing's stack into the buffer the hypercall sends; every
host printimmstack() prints it).  The forwarding statements carry no
predicates: the host evaluates each clause's predicate once per hypercall,
so a predicate with side effects (e.g. rand()) is no longer evaluated N
times.  `dt_vprog_squash`/`dt_vprog_reorganize` (which reordered but never
merged) were superseded and removed (`removed-vprog-squash.c`).
Regressions: `typing-vprog` (4 cases; before: 3 statements for a 3-action
clause, `vp.log`), `program-properties:vprog-grouping` and
`vprog-transform` (updated from the per-statement layout).  An end-to-end
check (a guest clause with 3 actions, the host consumer seeing each action
once per firing) needs the kernel harness; it is routed through the
coordinator.  No hypercall or ECB ABI changed.

**`checkStack` (`dt_typing_stack.cc`).** It returned an uninitialized stack
when there were none, compared `oni != stack->end()` (reading past a shorter
stack), did not compare the number of entries, and compared CTF ids across
type files.  Rewritten: entries counted, types compared by name across type
files.  Regression: `typing-units:stack-checks`.

**Fall-through edges (`dt_basic_block.cc`).** A block that ends only because
the next instruction is a branch target falls into it, but the CFG had no
edge, so definitions on the fall-through path did not reach the label: type
inference saw only the branch path's definition and accepted a register that
is a D string on one path and an integer on the other.  Regressions:
`typing-units:dfg-fall-through-into-a-label`,
`typing-reject:fall-through-definition-is-type-checked`.

**`getVariableInfo` (`dt_linker_subr.cc`).** It decoded stores only, so loads
were decoded again (and incompletely: scalars only) elsewhere.  It now
decodes every variable load and store and says which; `checkVarDefs`
requires a store, and the DFG and `findVariableFromNodeDefs` use it (a store
through a pointer loaded from an array element now has that array as its
variable source).  Regressions: `typing-units:variable-info-decoding`,
`variable-source-through-an-array-element`.

**`t | sym` (`dt_typing_var.cc`).** The address of a member is kept as the
structure pointer plus the member name.  Minimal valid D that was rejected:
`BEGIN { self->p = &curthread->td_tid; } END { self->p = (lwpid_t *)arg0; }`
("subtyping not possible: struct thread * != int *").  Fix: two values are
the same kind of pointer iff they point at compatible types (the member's
type for `t | sym`, libctf compatibility); a member address and the
structure pointer itself are different types (this was silently accepted).
Regressions: `typing-roundtrip:member-address-and-pointer-in-one-variable`,
`typing-units:same-target-of-member-addresses-and-pointers`,
`infervar-symbols`.

**Builtin types follow the D ident table.** arg0..arg9 and harg0..harg9 are
int64_t (were uintptr_t) and rand() is int (was uint64_t), as `dt_open.c`
declares them; the inference corpus's known-divergence list is now empty.
(The earlier `cpu` entry was spurious: the table and the library both say
int.)

**Resolver errors (`dt_elf.cc`).** `applyResolverFilter` treated every
non-zero `dt_resolve()` result as "another target" and dropped the
statement; when this machine's identity cannot be read (DT_RESOLVE_ERROR) the
parse now fails with the reason.  Regression:
`typing-roundtrip:target-filter-and-unreadable-identity` (gethostname and
kern.osrelease made to fail, as the frontend shim does).

## Dead functions

- `dt_typefile_first()`: a superseded leftover.  It is in the pinned
  upstream (`contrib/hypertrace/upstream/.../dt_typefile.cc:291`) without a
  caller there either, and a whole-tree grep finds no caller.  Removed.
- `HyperTraceELFParser::createElfStrData()`: was a placeholder; round 3
  wired it (print() output was degraded on the host; see Round 3).

## BOTTOM-typed return types: the trust gap and the options

**Threat.** For a host DIFO whose return type is BOTTOM (guest data), the
host accepts the guest linker's CTF kind (within the class allowed for the
return mode) and, for by-reference results, the size.  A compromised guest,
or a buggy guest linker, can therefore declare a by-reference record larger
than the object it names.  The host allocates the record from that size and
copies it from guest memory through the guest's address translation, so
host memory safety is not at stake; what is at stake is (a) the integrity of
what the consumer is told (a struct reported as an array, a size that
includes neighbouring guest memory, so data the clause did not ask for is
recorded), and (b) resources: oversized records exhaust the consumer's
buffers and cause drops for every other clause.

**Option 1: guest CTF on the host.** Obtain the guest kernel's CTF and redo
the guest's typing of BOTTOM results on the host, then verify kind and size
exactly.  Exact, and it would also let the host print guest types.  But CTF
sent by the guest is as untrusted as the claim it would check; it only helps
if the host gets it from a source it trusts (the image it booted, keyed by
the guest kernel's build identity).  Costs: per-guest-build CTF management
and megabytes per kernel.

**Option 2: a per-action size bound.** Bound every by-reference BOTTOM
result by a host-chosen limit (for example the strsize-like option per
action kind, or a new option with a conservative default), on top of the
class rule already in place.  Cheap, local to the verifier, and it closes
the resource attack; it cannot tell a truthful layout from a lie within the
bound.

**Recommendation.** Option 2 now: it bounds the impact with no new trust
dependency (implemented in round 3: `guestrefsize`).  Option 1 later, and
only with CTF from a trusted source (the host's copy of the guest image),
never guest-supplied CTF.

## Round 3

**print() type references through the ELF (`dt_elf.cc`): a correctness
bug.**  The host executes the program that comes back from the guest
through an ELF file (`dtrace.c`: `newpgpl->pgp = newprog`, parsed by
`dtrace_elf_parse()`).  The ELF did not carry `dtsd_strdata`, the CTF type
reference print() records ("module`id", `dt_cc.c`), so the DOF the host
enabled gave the print() record no format (`dt_dof.c`: format only from
`dtsd_strdata`), and the consumer (`dt_consume.c`) printed the value with
the plain trace() method: a scalar as a bare number without its type, a
structure as a hex dump of its bytes, instead of the typed output print()
promises.  Fixed: `createElfStrData()` stores the reference in the
identifier name table (reference = offset + 1; 0 means none) and the parser
restores it (bounds checked).  The verifier requires the returned program's
references to equal the host's (a guest could otherwise make the host print
memory as a type of its choosing; `program-verify-mutation` found exactly
that escape once the field was meaningful).  Regressions:
`typing-roundtrip:print-type-reference-survives-the-elf` (round trip and
the DOF's format string), `elf-coverage-matrix` (`strdata` accepted and
restored; a reference outside the table rejected).

**BOTTOM trust gap, option 2 implemented (`dt_program.c`, `dt_options.c`,
`dt_impl.h`; no kernel change).**  A by-reference CTF result of a
BOTTOM-typed base DIFO may declare at most `guestrefsize` bytes (default 64
KiB, `-x guestrefsize=size`; 0 or garbage is refused).  The kind rule is
unchanged.  Regressions: `program-verify-mutation` mutants
`ctf-byref-at-bound`, `ctf-byref-over-bound`, `ctf-byuref-over-bound` and
the `guestrefsize-option` check.  The 9 known-gap mutants that remain are
bit flips inside the allowed classes and bound (a guest can still lie
about which allowed kind, and about a size within the bound).

**`t | sym` in `checkVarDefs`.**  The definitions-agree checks now use the
same rule as stores (`sameValueType`: same type, or member addresses
pointing at the same type), and the LDLS rule's symbol checks were removed
(they rejected `&p->td_tid` against `&p->td_oncpu`).  Mismatch reports name
the members.  Regressions: `typing-units:same-value-type`,
`vardefs-untyped-variable-member-addresses`, `infervar-symbols`,
`typing-rules:ldls-store-checks`, `aa-load-symbol-mismatch`.

**New coverage tests:** string forms against a real `const char *`
(typingfix) and an unnamed type; names longer than a type name buffer;
`typeIsCompatibleWith` with a module without CTF; a forward in typingfix3
whose definition is in typingfix; `byRefStoredType` without a type file;
`varEqualCTF` with a different type file (library copy); probe arguments
joined across modules and from a module without a type file; args[] of a
probe without kernel CTF; all record sections past the end of the file
(`elf-coverage-matrix`).

## Findings outside this group (reported, not fixed here)

**Front end (dt_cg.c, dt_cc.c)**

- `BEGIN { trace(huregs[0]); }` crashes the compiler: SIGSEGV in `dt_cg`
  under `dtrace_program_strcompile`, with NODEV.
- The D compiler leaks about 2.9 KB per further statement of a clause, for
  example `BEGIN { x = 1; trace(x); }`.  Measured by subtracting
  compile-only growth; `dt_program_destroy` does not release it.
- An undeclared `self->` read was not reproduced as an abort.  With and
  without `ZDEFS`, NODEV and NOSYS, it is the diagnostic "self->undeclared
  has not yet been declared or assigned".

**dt_resolver.c**

- `dt_resolver.c` called `errx()` when `gethostname`/`uname` failed (routed
  to the frontend agent, who made it return DT_RESOLVE_ERROR; the ELF
  parser's handling of that is fixed above).

**Earlier findings still open**

- `updateDFG`: sets `child.second = false` on a copy.
- The TYPECAST symbol drops the module scope.
- Subtype "first" semantics differ between integers and structs.
- `updateUsetxDefs` is potentially exponential.

**Files outside the brief's ownership that were edited** (each needed for
the approved rework or by the coordinator's assignment):

- `dt_typing_stack.cc`: program errors, per-link stacks, `checkStack`;
- `dt_linker_subr.cc`: `getVariableInfo`;
- `dt_basic_block.cc`: assertion after `checkDIFO`, fall-through edges;
- `dt_subr.c`: `dtdo_types` freed, not copied by dup;
- `dt_impl.h`: `dt_set_progerr` returns int, with a format attribute;
- `dt_ident.c`: populate errors;
- `dt_program.c`: BOTTOM kind rule and size bound, print() references
  verified, the forwarding program (one statement per probe);
- `dt_options.c`, `dt_impl.h`: the `guestrefsize` option;
- `cmd/dtrace/dtrace.c`: `link_failed`.

Tests outside this group's new files that were updated:

- `coverage-cli.py`: re-reviewed denominators;
- `coverage-cli-cases.py`: `exec-program-type-error`;
- `linker-corpus.py`: a program error is now status 5, a returned failure;
- `program-verify-mutation.c`: kind and size-bound mutants;
- `elf-coverage-matrix.c`: print() references, record sections past the
  end of the file;
- `ctf-linker-bounds.cc`: a leading TYPECAST's symbol is checked;
- `program-properties.c`, `vprog-transform.c`: one forwarding statement
  per probe; the BOTTOM kind rule.

`frontend-runtime-open.py` (malloc sweep over all of `dtrace_open`) still
passes (`fe-d/`: 6049 checks).  Its open faults never reach a populate
failure outside a compilation, so the targeted case above covers that path.
Also passing: `frontend-parser-symbols`, `frontend-parser-oom` and
`frontend-codegen-oom`.

## Round 4 (2026-10-21): linker widths agree with the front end

The front end is D's source of truth, and the consumer formats each record
by it. D does not apply C's integer promotions (dt_type_promote()). Round 2
had typed linker arithmetic by C's rules, so some widths disagreed with the
front end. The linker now uses D's rules:

- **Return type (all classes).** relocateRet() keeps the compiler's
  dtdo_rtype whenever it is known (not BOTTOM). That is the type the front
  end recorded for the expression, and dt_prog_verify() already required a
  linked program to keep it. The linker types a result only when the
  compiler could not (BOTTOM: guest data).
- **Class 1, arithmetic and bitwise.**
  TypeInference::integerResultType() now uses dt_type_promote()'s rank rule:
  - rank = bits, plus 1 if unsigned; an enum counts as int;
  - the higher rank wins; on equal ranks, the larger resolved type id wins;
  - the result is that operand's own type;
  - a shift takes its left operand's type.
- **Class 4, constants.** A setx constant has the compiler's constant type
  for its value (int, long, then unsigned long, as dt_node_int()). It is no
  longer uint64_t. ldx stays uint64_t.
- **Class 2, comparisons.** The 0/1 result is a setx constant, so it is an
  int (4 bytes). The return type is the compiler's int in any case.
- **Class 3, unary operators and ?:.** These already agreed and are
  unchanged.
- **Union members.** The symbol rule in dt_typing.cc refused a member of a
  union (only struct and forward were accepted). It now accepts unions; the
  regression is `typing-roundtrip:struct-copied-into-clause-variable`
  (`*(union sigval *)arg0`).

**Oracle changes.** C stays the oracle only where D follows C.

- typing-oracle.h: C promotion is replaced by the rank rule, and setx is
  given its constant type.
- typing-rules: `arith-int-int-c-conversions` is replaced by
  `arith-int-int-d-ranks`. It uses an independent rank computation from
  libctf encodings, cross-checked against the compiler's return size.
  `arith-int-and-constant` now expects the higher-rank operand's type, and
  the setx cases expect int, long or unsigned long.
- typing-casts: casts still follow C. `(char)arg0 >> 1` is now a 1-byte
  char, as D types it.
- typing-units:
  - `ret-rtype-compiler-type-is-kept` is new, for the value and by-reference
    cases;
  - `ret-rtype-linker-typed-results` is new, for a BOTTOM base, no base,
    the default action kind, and a userland string by reference;
  - RetUnit now uses a BOTTOM base.
- typing-reject: the array-member case uses a BOTTOM base.
- coverage-cli-cases.py: `trace(1)` and `trace(5)` are 4-byte int records,
  so the expected output now pads to width 8, not 16.

**Results** (library efb4778e…, built under the shared lockf):

| Suite | Result |
|---|---|
| frontend-codegen-link.py | `PASS: 824 front-end/linker typing cases`; agreement.json is `[]`, so there are no width or value disagreements |
| typing-inference.py | 648 cases in 16 harnesses |
| linker-corpus, linker-offline, ctf-linker-bounds, program-verify-mutation | pass |
| elf-coverage-matrix.py | pass |
| program-properties.py | pass |
| coverage-cli.py | 477/477 |

**Coverage, lines / branches (%):**

| File | Lines | Branches |
|---|---|---|
| dt_typing.cc | 99.48 | 98.31 |
| dt_typing_var.cc | 100 | 99.05 |
| dt_typing_reg.cc | 100 | 100 |
| dt_typefile.cc | 100 | 97.86 |
| dt_typing_helpers.cc | 99.31 | 97.50 |
| dt_dfg.cc | 99.65 | 98.88 |
| dt_hypertrace_linker.cc | 99.30 | 97.17 |
| headers | 100 | 100 |

dt_elf.cc was not changed and keeps its Round 3 figures.

### Round 4b (2026-10-21): constants carry their front-end type

**Problem.** Round 4 typed a setx constant by its value: int, then long,
then unsigned long. That loses the type of the literal. For example `1u`
became int, `0xffffffff` became long, `sizeof (int)` became int, and `-1`
(setx 2^64-1) became unsigned long. Fork A's linktype harness
(lib-frontend-20261021/A/linktype) still found 55 of 203 programs
disagreeing on the round-4 library; on the pre-round-4 library it had
found 79.

**Fix.** The fix needs no change to the DIFO or ELF format: it uses the
existing TYPECAST annotation (op 84, a symbol-table type name, which the
linker turns into a nop). The compiler already emitted it for folded
casts of constants.

- **Compiler side.** dt_cg.c (DT_TOK_INT) now also emits TYPECAST
  `<front-end type>` after a constant's setx, but only when that type
  differs from the type the value implies. Most constants are small ints
  and get no extra instruction. The value is unchanged: `-1` still loads
  2^64-1, now annotated as `int`.
- **Linker side.** In dt_typing.cc, a TYPECAST of an integer constant now
  keeps the constant's value and nullness (`integer` and `isNull`). The
  arithmetic rank rule then sees the literal's own type.
- **Old guests.** A guest built by an older compiler does not annotate,
  so its constants are still typed by their value.

**New harness.** `typing-linktype.cc` is now part of typing-inference.py
and requires full agreement between the front end's type for `this->r`
(its variable table) and the linker's type for the arithmetic
instruction. Cases:

| Case | Programs |
|---|---|
| `constant-literal-types-agree` | 7 types × 30 constant operands: fork A's 22 plus `1ll`, `0x7fffffff`, `0x7fffffffffffffff`, `0xffffffffffffffff`, `- 2147483648`, `\| -0x80000000`, `1 ? 2u : 3u`, `-(1u)` |
| `variable-operand-types-agree` | the 49 variable pairs |
| `stored-constant-sum-reused` | stored intermediates used again |
| `annotated-constant-keeps-value` | the annotation is present only when needed, becomes a nop, and the value is kept |

**Results** (library 126860a7…, built under the shared lockf):

| Check | Result |
|---|---|
| Fork A harness | 203/203 agree |
| typing-linktype | 210 + 49 + 3 programs agree |
| typing-inference.py | 652 cases in 17 harnesses |
| linker-corpus, linker-offline, ctf-linker-bounds, program-verify-mutation | pass |
| elf-coverage-matrix, program-properties | pass |
| coverage-cli | 477/477 |
| frontend-codegen-link | 824 checks, agreement.json `[]` |
| frontend-codegen-arith, -cc, -lang | pass |
| frontend-codegen-oom, -unit | pass (run before the guard removal) |
| frontend-parser-fold, -corpus | fold re-run on the final library; corpus passed before the guard removal |

The new dt_cg.c branches are all covered.

**Coverage, lines / branches (%):**

| File | Lines | Branches |
|---|---|---|
| dt_typing.cc | 99.48 | 98.47 |
| dt_typing_var.cc | 100 | 99.05 |
| dt_typing_reg.cc | 100 | 100 |
| dt_typefile.cc | 100 | 97.86 |
| dt_typing_helpers.cc | 99.31 | 97.50 |
| dt_dfg.cc | 99.65 | 98.88 |
| dt_hypertrace_linker.cc | 99.30 | 97.17 |

### Round 4c (2026-10-21): no TYPECAST reaches the kernel

**Problem.** The kernel's DIF validator has no case for DIF_OP_TYPECAST
and refuses it as an invalid opcode. Only dtrace(1) links programs
(hypertrace_link turns the annotation into a nop). lockstat, plockstat and
bsdinstruments execute compiled programs directly, and dt_dof.c copied
the DIF unchanged. Folded casts of constants already hit this; round 4b
made it common.

Before the fix (library 126860a7…), the real tools sent TYPECAST
instructions to the kernel:

| Tool | TYPECAST in DOF |
|---|---|
| lockstat | 40 |
| lockstat -H | 88 |
| lockstat -A -s 8 | 204 |
| plockstat | 34 |

**Fix (dt_dof.c, dof_add_difo).** The DIF section of every DOF is written
with each TYPECAST replaced by DIF_INSTR_NOP. This covers
dtrace_program_exec, the anonymous/-G DOF and the error program. The
program in memory and its ELF serialization keep their annotations. A
linked program has none left, so it is unchanged.

**Tests.**

- **typing-roundtrip.cc:**
  - `kernel-dof-has-no-typecast`: dtrace_dof_create, stripped and
    unstripped;
  - `kernel-dof-from-program-exec-has-no-typecast`: a dtrace_vopen
    handle whose ioctl vector receives DTRACEIOC_ENABLE, i.e. the exact
    DOF dtrace_program_exec builds;
  - `annotated-constants-link-verify-roundtrip`: the guest ELF keeps the
    annotations; building DOF changes nothing; the program links,
    verifies and round-trips; nothing is left after linking.
  - The programs are `-1`, `1u`, `sizeof (int)`, a folded `(char)300`,
    and a predicate with `-1` and `1l`. Each case first requires the
    program to carry annotations.
- **tool-dof (typing-inference.py, using tool-dof-shim.c):** builds
  lockstat.c/sym.c and plockstat.c from their sources and wraps their
  library entry points (`-Wl,--wrap`), so each tool runs its own program
  generation and its own `dtrace_program_exec`:
  - `dtrace_open` becomes `dtrace_vopen` with a vector that reads the
    ENABLE DOF and models the kernel's lockstat probes;
  - `strcompile` adds ZDEFS, and plockstat's `plockstat$target` becomes
    `plockstat`;
  - `symtab_init` is skipped (no /dev/ksyms and no kldload);
  - runs: 8 lockstat option sets and 4 plockstat sets. Each run requires
    0 TYPECAST in the DOF and more than 0 annotations in the program.
- **program-properties.py:** its DOF oracle now expects a nop where the
  program has a TYPECAST.

**Results** (library c8975159…):

| Check | Result |
|---|---|
| typing-inference.py | 667 cases in 18 harnesses, tool-dof 12/12 |
| linker-corpus, linker-offline, ctf-linker-bounds, program-verify-mutation | pass |
| elf-coverage-matrix | pass |
| program-properties | 122 |
| coverage-cli | 477/477 |
| fork A harness | 203/203 agree |
| frontend-codegen-arith | 2450 |
| frontend-codegen-cc | 170 |
| frontend-codegen-lang | 32 |
| frontend-codegen-link | 824, agreement.json `[]` |
| frontend-parser-fold | 1716 |
| frontend-parser-corpus | 840 |
| compiler-offline | 102 (DOF checked) |
| pid-placement | 101 |
| enable-ioctl | pass |

Both outcomes of the new dt_dof.c branch are covered. Coverage of this
group is unchanged from round 4b.

### Round 4d (2026-10-21): linking is a property of execution

**Problem.** The kernel agent ran the captured tool DOFs through the real
dtrace_dof_slurp/dtrace_difo_validate. All 8 lockstat runs were refused:
they carried USETX (2–116 per run) and ULOAD (1–58 per run), which only
hypertrace_link resolves and which only dtrace(1) called. The same counts
were captured here, before the fix, with lockstat built from its own
source and run through tool-dof-shim. The output is in
`lib-typing-20261021/tooldof/before-link-fix.txt`, for example:

```
lockstat: usetx=40 uload=20
lockstat -A -s 8: usetx=116 uload=58
plockstat: 0
```

**Fix (dt_dof.c).** `dtrace_dof_create()` now links any program that
still holds USETX, ULOAD or UULOAD, using `hypertrace_link()`, before
building DOF. That one function serves every path to the kernel:

- dtrace_program_exec;
- dtrace_augment_tracing;
- dtrace(1)'s anonymous `-A` DOF;
- `-G` objects;
- the error program (dtrace_geterr_dof).

**Behavior:**

- **Idempotent.** A linked program has none of these instructions:
  dtrace(1)'s own programs, a guest's program the host linked and
  returned, and vprog forwarding programs are left exactly as they are.
  Nothing is linked twice.
- **TYPECAST-only programs are not linked.** TYPECAST is only an
  annotation, and dof_add_difo still turns it into a nop. That rewrite is
  now a required part of the design, not just a backstop. Such programs
  run as the compiler produced them, and they keep their annotations for
  their ELF. This also covers programs the linker cannot type, such as
  dynamic translators (XLATE/XLARG are unhandled in the type checker).
- **Errors.** A failed link is returned through the existing error path,
  never by exiting:
  - EDT_COMPILER, with the type checker's dp_err or the linker's message;
  - EDT_NOMEM for allocation failure.
- **Digest unchanged.** `dtrace_program_compiled_digest()` uses the new
  non-linking `dt_dof_create()`, because it identifies the compiled
  program before it is forwarded.

**Allocation safety.** Running the linker under exec exposed that it
aborted on any allocation failure: libdtrace's C++ was built with
`-fno-exceptions`, so a failing `new` terminated the process.
program-properties' fault-exec sweep failed 261 times with SIGABRT.

- cddl/lib/libdtrace/Makefile now builds the C++ sources with exceptions.
- `hypertrace_link()` catches `std::bad_alloc`, releases the type files,
  and returns E_HYPERTRACE_SYS with ENOMEM. The program may be partly
  relocated and must not be executed.
- libctf reports allocation failure as EAGAIN, so `Typefile::getTypename`
  now throws `bad_alloc` in that case instead of reporting a program
  error.
- fault-exec now passes (289 iterations).

**Tests.**

| Location | Case or check |
|---|---|
| tool-dof (tool-dof-shim.c) | counts TYPECAST, USETX, ULOAD and UULOAD in the DOF and requires 0 of each, with link-time instructions present in the compiled program; 12/12 pass (they failed before) |
| typing-roundtrip | `unlinked-program-linked-for-the-kernel`: `((struct proc *)arg0)->p_pid + \`hz`, `curthread->td_proc->p_pid`, and a predicate with `\`maxproc`. Each holds USETX or ULOAD. The DOF holds none of the four, and its DIF, INTTAB and DIFOHDR sections equal those of the same program after dtrace(1)'s link and verify. A second DOF is identical. |
| typing-progerr | `kernel-dof-link-error-returned`: a program error and a non-program link failure are both returned as EDT_COMPILER with their messages; a TYPECAST-only ill-typed program is not linked |
| typing-progerr | `kernel-dof-needs-link-by-instruction` |
| typing-progerr | `kernel-dof-link-allocation-failure-returned`: every one of 225 allocations failed in turn; 219 returned EDT_NOMEM, 6 were absorbed, none were bad |
| typing-units | `typecompare-unnamed-first/second` and `typename-allocation-failure-throws` |
| program-properties.c | fault-exec now prints the error message when it reports a failure |

**Results** (library 366e36ea…):

| Check | Result |
|---|---|
| typing-inference.py | 674 cases in 18 harnesses, tool-dof 12/12 |
| linker-corpus, linker-offline, ctf-linker-bounds, program-verify-mutation | pass |
| elf-coverage-matrix | pass |
| program-properties | 122, including fault-exec |
| coverage-cli | 477/477 |
| fork A harness | 203/203 agree |
| frontend-codegen-arith | 2450 |
| frontend-codegen-cc | 170 |
| frontend-codegen-lang | 32 |
| frontend-codegen-link | 824 |
| frontend-parser-fold | 1716 |
| frontend-parser-corpus | 840 |
| compiler-offline | 102 |
| pid-placement | 101 |
| enable-ioctl | pass |

**Coverage, lines / branches (%):**

| File | Lines | Branches |
|---|---|---|
| dt_typing.cc | 99.48 | 98.47 |
| dt_typing_helpers.cc | 99.31 | 97.50 |
| dt_typefile.cc | 100 | 97.92 |
| dt_hypertrace_linker.cc | 99.44 | 97.39 |
| total | 98.96 | 97.90 |

### Round 4e (2026-10-21): dynamic translators; host global-variable round trip

**XLATE/XLARG rules.**

- **dt_typing.cc.** XLATE and XLARG are typed from the DIFO's translator
  table: `dtdo_xlmtab[DIF_INSTR_XLREF]` is the translator member node, and
  its type is the result's type. This applies to both opcodes, because
  in dt_cg both leave the translated member's value in rd; XLARG differs
  only in taking the probe argument as its input.
  - Lookup order: a string member becomes DIF_TYPE_STRING; otherwise D's
    container is tried first, then `dt_autoresolve_ctfid`, as for
    TYPECAST.
  - Each failure is a program error: no table, an entry past the table, a
    null entry, XLATE without a defined input, a member with no name, or
    a type no container has. libctf's EAGAIN becomes bad_alloc.
- **dt_dfg.cc and dt_linker_subr.cc.** XLATE and XLARG define rd, and
  XLATE uses rd as its input, so def-use chains run through them.
- **Opcode coverage.** Every DIF opcode now has a typing rule; "unhandled
  instruction" is reached only for an invalid opcode.

**Limits.**

- **The kernel has no XLATE, XLARG or XLTAB support.** Nothing for them
  appears in dtrace.c, so the DIF validator refuses them, as it does
  TYPECAST. A dynamic-translation program can now be linked and verified,
  and its DOF carries the XLTAB, but no kernel path can enable it. Its
  values therefore can't be compared with the static path by running it.
  The tests compare result type and record size instead.
- **The ELF does not carry dtdo_xlmtab.** The table holds pointers to the
  compiler's translator members. A guest→host program with dynamic
  references is reported as a program error ("not in the 0-entry
  translator table") instead of being mistyped. Carrying it would be an
  ELF format change, which I am proposing rather than implementing.
- **Pre-existing, unchanged:** the type checker cannot type `args[]` of a
  probe declared by the program itself (LDGA), so the static variant of
  the test program is compared unlinked.

**XLATE/XLARG tests.**

- **typing-rules:** 12 unit cases for the rule and each of its errors,
  including allocation failure.
- **typing-roundtrip:**
  - `dynamic-translator-links-and-verifies`: the program-properties
    xlate-import program, plus one that also uses
    `((struct proc *)arg1)->p_pid`. Each links, types the member as int,
    passes dt_prog_verify, and its DOF has XLTAB and none of USETX,
    ULOAD or TYPECAST. The unlinked kernel-member program is linked by
    dtrace_dof_create; it was refused before ("unhandled instruction: 79").
  - `dynamic-translator-type-matches-static`.
  - `dynamic-translator-through-the-elf`.
  - `dynamic-translator-table-checked`.
- **program-properties.c:** xlate-import and xlate-import2 now run
  hypertrace_link (`*-links`, PASS), and their DOF cases still pass.

**Host round trip of a global variable.** The program
`dtrace:::BEGIN { x = 1; } dtrace:::END { trace(x); }` now runs end to end
in coverage-cli's fake-dtraced flow:

1. the consumer (`-E`) sends its base ELF;
2. a real `dtrace -Y base.elf,host` links it in process_elf_hypertrace and
   publishes it inbound;
3. the consumer verifies and enables it;
4. the scripted END record prints `trace(x)` as a 4-byte int.

The host accepts and runs it on the current library.

- The sender path already links before serializing: process_elf_hypertrace
  calls hypertrace_link before dtrace_elf_create. dtrace.c needed no
  change.
- The original rejection ("typecast was not set to nop") came from an
  unlinked program reaching a consumer. Real dtraced never routes one
  there, so the remaining causes were already fixed: the ckind fix
  (round 1) and the type-width fixes.
- New CLI case `host-roundtrip-global-variable`:
  - stdout must be exactly the header, plus `0 2 :END` with ` %8d` = 1;
  - stderr: `dtrace: matched 2 probes (<id>) from 0`;
  - the daemon must have received the base ELF and completed the stop.
  - guest_runner gained `target` and `direction` parameters, used here
    for `,host` and inbound.

**Results** (library 4bd1e7c5…):

| Check | Result |
|---|---|
| typing-inference.py | 700 cases in 18 harnesses |
| linker suites | pass |
| elf-coverage-matrix | pass |
| program-properties | 124 |
| coverage-cli | 478/478 (+1 new case) |
| fork A harness | 203/203 agree |
| frontend codegen suites | arith 2450, cc 170, lang 32, link 824 |
| frontend parser suites | fold 1716, corpus 840 |
| compiler-offline | 102 |
| pid-placement | 101 |
| enable-ioctl | pass |

**Coverage, lines / branches (%):**

| File | Lines | Branches |
|---|---|---|
| dt_typing.cc | 99.50 | 98.53 |
| dt_dfg.cc | 99.65 | 98.53 |
| dt_hypertrace_linker.cc | 99.44 | 97.39 |
| total | 98.97 | 97.86 |
