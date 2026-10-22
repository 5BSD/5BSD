# HyperTrace kernel and guest coverage (offline)

Owner: kernel/guest coverage agent. The coordinator merges this record into
COVERAGE.5BSD.md. Status: round 4 complete (2026-10-21).  "Round 4" adds the branch view
(lines AND branches); earlier rounds are kept for history.

## Round 4: branches (lines and branch outcomes of changed lines)

Evidence: coverage `/usr/obj/5BSD-hypertrace-validation/cov-kernel-round4b-20261021/`
and ASan+UBSan `cov-kernel-round4b-sanitize-20261021/` (they supersede the
earlier `cov-kernel-round4-*` runs, which predate the VM ID reuse and tool
DOF tests); the suites are dtrace_hypertrace, dtrace_vm_subr, virtio_dtrace
and dttransport, with `sources_unchanged: true` in both and 0 failures
(dtrace_hypertrace 131710 checks).  The numbers below are unchanged
between the two runs.  The vmm_hypertrace suite was not rerun: running it was
blocked by the permission classifier pending the user's approval (see
"Not done").  Pre-change copies: `cov-kernel-dtrace-prefix4-20261021/`.

### Branch view (coverage-kernel.py)
The plain view counts every llvm-cov lcov branch outcome on a changed line,
including outcomes inside macro expansions.  The new branch view splits
each line's outcomes into the conditions written in the file (JSON branch
regions) and macro outcomes (the rest), and waives uncovered ones only:
- by the line's own line waiver (same class);
- automatically for macro outcomes, from the expansion's own regions: the
  `assert` class (an assertion's failure test: ASSERT's EX/dtrace_assfail,
  KASSERT/MPASS/queue(3) QUEUE_MACRO_DEBUG panic guards) and the
  `macro-constant` class (`while (0)`, `__builtin_constant_p`, `_Generic`,
  sizeof dispatch, malloc(9)'s constant-flag tests, mutex_init()'s name
  literal).  A line with any other uncovered macro region stays open;
- by an explicit entry in `tests/kcov/branch-waivers.txt`
  (FILE|FUNCTION|CLASS|LINE|CONDITION or MACRO|T/F/*|REASON; LINE and
  CONDITION must match whole text).  Stale entries are reported.
New classes: `freebsd-constant` (cpu_intr_actv/CPU_ON_INTR are constant 0
on FreeBSD) and `race` (a locked re-check after an unlocked lookup).

### Results (changed-vs-HEAD; "unw" = excluding waivers)

| File | Lines (unw) | Branches | Branches unw | Open | Functions |
| --- | --- | --- | --- | ---: | ---: |
| dtrace.c | 3758/3980 (3758/3758) | 2097/2514 | **2097/2133 = 98.31%** | 36 | 122/124 |
| hypertrace.c | 517/530 (517/517) | 292/312 | 292/292 | 0 | 30/30 |
| hypertrace_map.c | 146/146 | 75/82 | 75/75 | 0 | 8/8 |
| dtrace_ioctl.c | 232/234 (232/232) | 120/128 | 120/120 | 0 | 1/1 |
| amd64/dtrace_isa.c | 120/134 (120/120) | 53/62 | 53/53 | 0 | 5/5 |
| dtrace_immstack.c | 57/69 (57/57) | 32/36 | 32/32 | 0 | 1/1 |
| dtrace_db.c | 133/142 (133/133) | 69/86 | 69/69 | 0 | 12/12 |
| amd64/dtrace_vm_subr.c | 164/164 | 109/118 | 109/109 | 0 | 6/6 |
| virtio_dtrace.c | 1643/1649 | 1234/1356 | 1234/1234 | 0 | 49/49 |
| dttransport.c | 365/365 | 183/212 | 183/183 | 0 | 20/20 |

dtrace.c waived branch outcomes by class: assert 92, macro-constant 63,
invariant 56, vm-tag 47, privilege 37, guest-args 33, live-only 30,
dominated-upstream 10, freebsd-constant 8, infeasible 5 (381 in all).
The 36 open dtrace.c outcomes are left uncovered and unwaived (each is
reachable in principle; listed in summary.json `branch_waived.open`): e.g.
the strtoll prefix edge, strcpy limit exit, bcmp mismatch, guest
copyoutstr wrap, the cleanpath strsize cut points, predicate-cache hits,
the global vprobe limit (256 Ki probes), vprobe_release_owner sharing
cases, and the immstack hash 1024-probe bound.

### Dominated checks removed (5BSD code, replaced by ASSERTs/KASSERTs)
dtrace.c: minion_stackarg_slot slot/base; memref dtms_probe NULL and
scratch-size wrap; getupcstack slots == 1; guest_varstr and json strsize
wraps (STRSIZE is a non-negative int64 option); ecb_create_enable cache
check; vprobe_create unlocks on vm > 0 paths (three); replicate pending;
bcopy destination wrap; ustack/jstack strsize < 0.  dtrace_isa.c: cached
`off >= maxoff`.  dtrace_vm_subr.c: valid_bit's PT_X86/default arms,
get_page's NULL pmap, and the page-walk loop exits (level 0 always ends a
walk).  hypertrace.c: map_count() error paths for VM 0/candidates,
htpb_epoch != 0, provider_reserve argument checks, epoch_byid bounds,
create_probes NULL vprobe, and check_epoch's per-probe loop (now an
INVARIANTS-only check; see below).  Upstream checks were kept (waived
dominated-upstream).  One upstream assertion was wrong for consumer input:
`ASSERT(nframes > 0)` after a zero STACKFRAMES/USTACKFRAMES/IMMSTACKFRAMES
option panicked the kernel (pre-fix log `nframes-option-assert-prefix.log`);
the record-size check refuses it (EINVAL), so the four asserts were
replaced by comments.  The validator's LDGA guest/host array ranges (an
unreachable 5BSD extension of an 8-bit field) were reverted to upstream.

### check_epoch invariant (coordinator review)
A VM ID is handed out only with an empty namespace (hypertrace.c:671/:677
via map_count(); hypertrace_map.c:169/:210 count every mapped probe);
release/destroy leaves probes ESTALE (:722) and quarantined; vm_reinit
reserves the new identity before releasing the old (vmm.c:865-884);
firing checks the live VM epoch (:484); unload refuses while probes exist
(:238).  Tested by case_ht_vmid_reuse (reuse refused, re-allocation
empty, rollback clean, reinit with probes present).

### Tests added
~70 DIF cases (page-crossing loads, top-of-space user loads/copies,
non-multiple-of-8 copies, untagged copyout sources, disallowed destructive
actions, execname absent/long, trap-frame/stack-pointer at the top, lock
subroutines in guests, substr/strchr/cleanpath/strjoin bounds, memref and
printm pair checks, by-ref stores, json literals, strtoll prefixes, host
string dynvar exhaustion), crafted DIF (host variables by ID, RLD* and
COPYS of guest NULL, SCMP wrap, JSON element, hypercall validator), and
direct cases in `t_dtrace_branches.inc` (epoch KPIs, probe_arg, predicate
cache, unanchored caller, empty VM, vprobe ioctls with logging, AUGMENT
errors, stack options, huge strsize, variable flags, GO during a pending
ENABLE, REPLICATE across consumers, provider table full (4096), late epoch
hook, empty descriptions, bad action strtab, dtrace_db.c symbol ties and
linker files, hypercall envelopes from jail/proc0 threads, VM ID reuse).
vprog end to end (coordinator request): one hypercall per guest firing,
host records of a 3-action clause once each and in order, twice on two
firings, and a predicate with a side effect evaluated once per firing.

### Tool DOF (coordinator request)
coverage-kernel.py captures the exact ENABLE DOF of lockstat (8 option
sets) and plockstat (4) with the typing agent's tool-dof-shim.c (included
unchanged by kcov/tool-dof-capture.c) and `case_tool_dofs` feeds them
through dtrace_dof_slurp()/dtrace_difo_validate(): no DOF carries
DIF_OP_TYPECAST; plockstat's are accepted; lockstat's are refused because
they carry DIF_OP_USETX/DIF_OP_ULOAD (link-time placeholders only the
HyperTrace linker resolves) -- reported to the typing agent.  The test
asserts acceptance exactly when a DOF has no link-time opcode, so it flips
to 12/12 without edits once libdtrace resolves them.  A literal-cast
program (-1, 1u, sizeof (int), (char)300) compiled without linking is
accepted with the expected record values; a crafted DIF_OP_TYPECAST is
refused.

### vmm suite (after the user's approval)
Evidence: coverage `cov-kernel-vmm-round4-20261021/`, ASan+UBSan
`cov-kernel-vmm-round4-sanitize-20261021/` (`sources_unchanged: true`,
vmm_hypertrace 1214 checks, 0 failures).  Changed-vs-HEAD, excluding
waivers: vmm.c lines 321/321, branches 179/179; vmm_dev.c 118/118 (one
gap line), branches 76/76; vmm_dev_machdep.c 24/24 (three gap lines),
branches 8/8; x86.c 6/6.
- VM_FREE_MEMSEG (coordinator's implementation, reviewed; the global
  destroy_dev_drain() hang was fixed with a per-VM pending count): success,
  reserved words 0/1/2 (EINVAL), out of range (EINVAL), unallocated
  (ENOENT), system memory (EINVAL), still mapped (EBUSY), double free
  (ENOENT), mmap of a freed node before its asynchronous destruction
  (ENXIO), reallocation of the ID, three pending frees removed from head,
  middle and tail of the devmem list, destroying a VM while another VM holds
  devmem (no wait), destroying a VM with a free pending (waits for it), and
  no leaked segment objects.
- VM_GET_RUN_WITNESS `_IOR('v', 201, struct vm_run_witness)` = { uint64_t
  epoch; uint64_t guest_entries; uint16_t vmid; uint16_t reserved0;
  uint32_t running_vcpus; uint32_t reserved[4]; } (40 bytes, amd64): zero
  for a new VM, matches VM_GET_IDENTITY, counts every guest entry (2 per
  hypercall exit, monotonic), counts a running vCPU, and is reset by
  VM_REINIT.
- VMMCTL_VM_LIFETIME_QUERY `_IOWR('V', 200, struct
  vmmctl_vm_lifetime_query)` = { uint64_t epoch; uint16_t vmid; uint16_t
  reserved[3]; char name[VM_MAX_NAMELEN + 1]; }: matches VM_GET_IDENTITY,
  follows VM_REINIT, EINVAL (no NUL, reserved), ENOENT (unknown, being
  destroyed, destroyed), EPERM for another uid or jail without
  PRIV_VMM_DESTROY.
- Harness: khx_vmm.c memory-segment model (alloc/get/free/mmap/munmap/
  getnext, referenced objects), khx_kern.c destroy_dev_sched_cb() queue and
  mmap entry, and the MAC memseg-access check.

### Tool DOF after the libdtrace link fix
With libdtrace sha256 366e36ea...be70 the 12 recaptured DOFs carry no
link-time opcode and all 12 are accepted by dtrace_dof_slurp() and the
DIF validator (case_tool_dofs, unchanged).

### Not done
- virtio_dtrace.c: 6 changed lines from earlier rounds remain uncovered
  (99.6% lines); its branches are complete.

### Build frontend (AGENTS.md)
No build inputs, staging, signing or publication changed; build-bsd needs
no update (/usr/src not edited).

## Round 3 (supersedes round-2 numbers, waivers and gaps)

Evidence: coverage `/usr/obj/5BSD-hypertrace-validation/cov-kernel-round3-20261021/`,
ASan+UBSan `cov-kernel-round3-sanitize-20261021/` (both `sources_unchanged:
true`, all five suites 0 failures, no stale waivers).  Pre-fix copies and
logs: `cov-kernel-dtrace-prefix3-20261021/`.

### Results (changed-vs-HEAD lines; waived view)

| File | Changed lines | Excluding waived | Branches | Functions |
| --- | ---: | ---: | ---: | ---: |
| dtrace.c | 3750/3973 | **3750/3750 (223 waived)** | 1979/2526 | 122/124 (filterfind, priv_probe) |
| amd64/dtrace_isa.c | 119/133 | 119/119 (14 live-only) | 52/62 | 5/5 |
| dtrace_db.c | 130/142 | 130/130 (12) | 61/86 | 12/12 |
| dtrace_immstack.c | 57/69 | 57/57 (12 live-only) | 32/36 | 1/1 |
| dtrace_ioctl.c | 231/234 | | 113/128 | 1/1 |
| hypertrace.c / hypertrace_map.c | 510/527, 146/146 | | 298/324, 75/82 | 30/30, 8/8 |
| dtrace_vm_subr.c | 163/167 | | 106/112 | 6/6 |
| dttransport.c / virtio_dtrace.c | 365/365, 1643/1649 | | 183/212, 1234/1356 | 20/20, 49/49 |
| vmm.c / vmm_dev.c / x86.c / vmm_dev_machdep.c | 307/307, 27/27, 6/6, 17/19 | | | |

Run sizes: dtrace_hypertrace 127104 checks, virtio 37567, dttransport
12203, vmm_hypertrace 1104, dtrace_vm_subr 145.

### Dominated checks: split
- Removed from 5BSD/HyperTrace code (and replaced by ASSERTs naming the
  earlier check): the dtrace_dynvar key-size and nkeys bounds; the
  guest_varstr wrap; the guest_ucaller/ustackdepth FAULT returns; the
  HYPERCALL frame bound; the SYM/MOD/UADDR, breakpoint and panic vmid
  checks; the guest_load guard; the enabling_list list/count checks; the
  guest_copyout source NULL/wrap check (COPYOUT/COPYOUTSTR admit the
  source first, through canload_tagged/strcanload or istoxic, whose table
  starts at 0); the strtok `limit < addr` check; dtrace_isa.c
  stack/stack_start alignment and the pc==0 / size<3 "??" branch;
  dtrace_immstack.c offset-room check.
- Kept, waived `dominated-upstream` (11 lines in dtrace.c, 3 in
  dtrace_db.c): rindex canload len+1, json canload jsonlen+1, strjoin
  scratch, inet_ntop AF else, dtrace_match by probe ID (no FreeBSD path
  sets dtpd_id), dtrace_symbol_values NULL symbol (from ddb).

### Covered this round
Helper provider (DTRACEHIOC_ADDDOF, ustack helpers with predicates,
relocations SETX/DOFREL and a misaligned one, fork duplication, exit
destroy); anonymous tracing (preloaded dof-data lines, boot enabling, dist
notification with the anon DDTRACEARG, grabanon takeover, unload of an
unclaimed state); the state_immstack allocation failure (sweep of every
NOWAIT allocation of GO with manual resize); jstackstrsize > UINT32_MAX;
the ENABLE probe list with an over-long provider name; guest struct
dynvar keys at NULL; execargs past the address-space top; CTF tuple
pushes of a tagged NULL into index/strstr/substr/json/toupper/basename;
hcaller in an unanchored guest probe; immstack with no walkable frames and
with 8/16/60-byte slots; ELF symbol ties and exact matches in dtrace_db.c.

### Bugs fixed (regression + pre-fix evidence)
1. Anonymous state leak (upstream FreeBSD): dtrace_dtr() and dtrace_unload()
   destroyed the anonymous dtrace_state_t without freeing it (21336 bytes
   per anonymous boot).  Fixed in dtrace.c and dtrace_unload.c; the anon
   cases assert zero live solaris allocations.  Pre-fix log
   `anon-state-leak-prefix.log`.
2. Probe-context hang (5BSD dtrace_isa.c): the trailing empty-frame loop in
   dtrace_getpcstack_generic() ignored populate_stack()'s failure, which does
   not advance depth, so a slot size of 8 (or misaligned) with no walkable
   frames looped forever.  Now stops on failure.  Pre-fix backtrace
   `immstack-fill-loop-hang.txt`; regression `case_immstack_noframes`.

### Waiver classes (round 3)
vm-tag 62, privilege 61, guest-args 15, invariant 39 (+6 dtrace_db.c),
dominated-upstream 11 (+3), future-feature 10 (dtrace_filterfind: unwired
machine filter, DTRACEIOC_FILTER returns ENOTTY until designed), infeasible
3 (dynvar key-size sum > SIZE_MAX needs >2^63 bytes of keys), gap 1,
live-only 21 (+14 dtrace_isa.c, +3 dtrace_db.c, +12 dtrace_immstack.c).

### Live-only (to run under QEMU only if the user approves)
Faults while reading kernel symbol tables or copying symbol names in probe
context (dtrace_isa.c, dtrace_db.c, dtrace_immstack.c); host strings ending
at a mapped top page (tolower, strncmp, strcpy, bcmp); bcopy backward
fault; hypercall stack-walk faults; guest_copyout host source fault after
admission.

### Not done
VM_FREE_MEMSEG (coordinator request): my edit to sys/dev/vmm/vmm_dev.c was
refused by the permission system; the design was sent to the coordinator
and nothing was changed.

### Build frontend (AGENTS.md)
No build inputs, staging, signing or publication changed; build-bsd.c and
its targets need no update (noted, /usr/src not edited).

## Round 2 (supersedes round-1 tables, gaps and decisions)

Evidence: coverage `/usr/obj/5BSD-hypertrace-validation/cov-kernel-round2-20261021/`
(`sources_unchanged: true`), ASan+UBSan `cov-kernel-round2-sanitize-20261021/`
(all five suites 0 failures).  Pre-fix evidence for this round:
`cov-kernel-dtrace-prefix2-20261021/` (dtrace.c), `cov-kernel-vmm-prefix2-20261021/`
(vmm.c), `cov-kernel-guest-invariants-prefix-20261021/` (virtio/dttransport).

### Results (changed-vs-HEAD unless noted)

| File | Changed lines | Changed branches | Changed functions | Whole-file lines |
| --- | ---: | ---: | ---: | ---: |
| dtrace.c | 3702/4008 (92.4%); **3702/3746 = 98.83% excluding 262 waived** | 1962/2548 | 118/124 | 9227/12678 |
| dtrace_ioctl.c | 231/234 | 113/128 | 1/1 | 737/791 |
| hypertrace.c | 510/527 | 298/324 | 30/30 | 507/524 |
| hypertrace_map.c | 146/146 | 75/82 | 8/8 | 144/144 |
| amd64/dtrace_isa.c | 118/145 | 48/66 | 5/5 | 372/582 |
| dtrace_db.c | 123/142 | 53/86 | 10/12 | 122/141 |
| dtrace_immstack.c | 57/72 | 32/36 | 1/1 | 57/72 |
| amd64/dtrace_vm_subr.c (new file) | 163/167 | 106/112 | 6/6 | 163/167 |
| dttransport.c | 365/365 | 183/212 (source 144/144) | 20/20 | 365/365 |
| virtio_dtrace.c | 1643/1649 | 1234/1356 (source 968/972) | 49/49 | 1590/1596 |
| amd64/vmm/vmm.c | 307/307 | 173/182 | 25/25 | 733/2237 |
| dev/vmm/vmm_dev.c | 27/27 | 22/22 | 4/4 | 332/1615 |
| amd64/vmm/x86.c | 6/6 | 0/0 | 1/1 | 66/389 |
| amd64/vmm/vmm_dev_machdep.c | 17/19 (2 gap lines) | 6/6 | 1/1 | 24/477 |

Waivers (`tests/kcov/waivers.txt`, applied by coverage-kernel.py, which
reports the plain and the waived view and lists stale waivers; none are
stale): each waiver names a function, a guard regex and a reason.
Classes: vm-tag 62 lines (a guest-tagged value on a host probe or another
VM's handle), privilege 61 (FreeBSD states always hold all privileges:
state credential = cdev si_cred = NULL), guest-args 15 (virtual probes
fire only via hypertrace_probe(), which always passes arguments),
dominated 85 (the condition was refused earlier on every path; each entry
names that check), invariant 38 (internal-consistency panics and bounds
that the named callers cannot violate), gap 1 (LLVM gap region).

Run sizes: dtrace_hypertrace 126359 checks (2 expected panics), virtio
37567, dttransport 12203, vmm_hypertrace 1104 (9 expected panics),
dtrace_vm_subr 145.

### What was added for dtrace.c

- Fault sweep: every guest case is rerun with its 1st, 2nd, ... guest
  memory access failing once (EFAULT, as if another vCPU had unmapped the
  page), geometric beyond 64 accesses; oracle: no crash or leak, only
  BADADDR/BADSTACK ERROR records or the normal output.  ~3000 runs.
- Scratch exhaustion per case (bisection of an alloca() prefix), string
  sizes 0/4/512, a guest that maps page zero, strings ending at the top of
  the address space, VMM copy failures, user-space top window.
- Hand-assembled DIF (`case_crafted_dif`) for opcodes the compiler never
  emits (ALLOCS, COPYS, RLD*, LDTA, sized PUSHTR, LDGA beyond arg9) and
  untagged addresses in guest clauses.
- Provider and module edges: getargval, condense, probe_arg, defunct
  provider reaping (taskq), REPLICATE by probe ID and across origins,
  hypertrace enable/disable hook failures, EXDEV across VMs, vprobe limits
  (64Ki per VM, 64 MiB of tables), immstack cache collisions, GO
  allocation-failure sweep, dists on STOP, host breakpoint() and panic()
  actions (the latter as an expected panic), lock subroutines with
  installed lock classes, signed/unsigned comparison extremes.

### Bugs fixed in round 2 (each with a regression; pre-fix logs in the
prefix2 directory)

11. rw_write_held/rw_iswriter/sx_exclusive_held/sx_isexclusive took the
    lock's first word (lo_name) as the lock (one dereference too many;
    upstream FreeBSD).  Regression: `lock-subroutines` (crashed before,
    `run-locks-bcopy-prefix.log`).
12. bcopy()/copyinto() reported regs[rd] instead of the destination as
    the fault address (upstream).  Regression: g_bcopy_dst/g_copyinto_dst
    host cases.
13. A NULL guest string in a string comparison was read from guest
    address 0 (BADADDR, or garbage if the guest maps page zero) instead of
    comparing as the empty string as for host pointers.  Regression:
    f_strcmp/f_strcmp2 NULL cases with and without page zero
    (`run-guest-null-strcmp-prefix.log`).
14. DIF_OP_CMP set cc_v = 0, so signed branches were wrong when the
    subtraction overflows (`INT64_MIN <= 1000` was false; upstream).
    Fix: two's-complement overflow flag.  Regression: c_cmp table, C as
    oracle (`run-cmp-overflow-prefix.log`).
15. Zero-length guest accesses (bcopy(p, d, 0), copyout(.., 0), strtoll
    with strsize 0) faulted BADADDR while host ones succeed.  Fix:
    dtrace_canload_tagged() allows sz == 0.  Regression: p_bcopy0,
    e_copyout0, z:f_strtoll (`run-zero-length-guest-prefix.log`).
16. virtio_dtrace.c (helper): SESSION_STOP/CLEANUP compared the control's
    identity with the node identity before taking vtdtr_ctrlmtx, so a
    stop retransmitted for the old identity just after COMMIT could stop
    the new session under the retired identity and wedge the transport.
    Fix: compare under the mutex.  Regression: `stop-activation-race`.
17. amd64 vmm.c (helper): HYPERCALL_TEST is now ring 0 only (the CPL table
    already gated PROTOTYPE and DTRACE_PROBE at ring 0) and its printf is
    rate-limited (1/s); hw.vmm.hv_mode tunable rejects invalid values
    (EINVAL) instead of silently selecting bhyve; hypercall_copy_arg's
    unreachable length check became a KASSERT plus a CTASSERT.  Guest-
    visible: TEST from ring 3 now returns ERROR.

### Dead code (re-grepped across sys/, cddl, lib, usr.sbin, contrib/hypertrace)

Removed (superseded leftovers; provenance via contrib/hypertrace/upstream):
dtrace.c dtrace_vmloadmem, dtrace_strcmp (the live path is the bounded
dtrace_strncmp; tests/pagewalk.{py,c} switched to it and pass:
`cov-kernel-pagewalk-20261021/`), dtrace_epid2size (uncalled, also
upstream), virt_state/virt_state_callout/dtrace_virt_state_tick and the
`|| state == virt_state` test; dtrace_addrxlate is now under `#ifdef
illumos` with its only (illumos-only MSGSIZE) callers.  dtrace_vm_subr.c:
DTRACE_DMAP_TO_PHYS, the four index helpers, dtrace_canonical_check and
the dtrace_pml4e..dtrace_pde_to_pte chain (replaced by the generic
dtrace_get_page walk).  dtrace_db.c: dtrace_linker_elf_search_symbol and
dtrace_symbol_is_ambiguous.  Not dead: dtrace_condense (fasttrap, kinst;
now tested), dtrace_immstack_invalidate_cache (kld_unload; tested).

virt_state was a planned kernel-owned DTrace session for guest probes
with no userland consumer: dtrace_virt_state_tick refreshed
dts_laststatus (a keepalive standing in for DTRACEIOC_STATUS so the
deadman would not abort it) and GO activated its buffers per CPU like the
anonymous state.  Nothing ever created or set it (here or upstream); the
live design uses ordinary consumer sessions plus dtpr_vmid.

Unwired feature, left for the user: dtrace_filterfind() belongs to an
unfinished "machine filter" (dtrace_machine_filter_t, DTRACEIOC_FILTER =
_IOW('x',19), dts_filter, DTRACEFILT_MAX).  No ioctl handler exists
(DTRACEIOC_FILTER returns ENOTTY), nothing reads dts_filter, no consumer
issues it.  Wiring needs an ioctl that installs a per-state VM-name
filter, a match-time check for dtpr_vmid != 0 probes, and a libdtrace
call; the semantics are unspecified and VM selection already works via
dtpd_target/vmname.  Its 10 lines are the largest unwaived gap.

### Remaining unwaived gaps in dtrace.c (44 lines)

dtrace_filterfind (10, decision above); helper-provider paths
(dtrace_helper 4, dtrace_action_ustack 2, dtrace_dof_relocate 1: need
ustack helpers registered via the helper device); anonymous tracing
(dtrace_buffer_activate_cpu 2, the anon dist branch 5); state_immstack
allocation failure (12; the GO allocation sweep does not reach it before
an earlier allocation fails); guest copyout source checks (5:
NULL/wrapping untagged host sources); dtrace_match by probe ID (2; no
consumer path supplies an ID); 15430 ustack strsize (1).
Other files: dtrace_isa.c 27 and dtrace_db.c 19 open changed lines are
mostly faults while reading kernel symbol tables in probe context and
misaligned record buffers (not reproducible without a kernel fault
handler); dtrace_immstack.c 15 the same.

### Findings for others / upstream (not fixed)

- Host store_by_ref keeps loading after a fault, so ERROR's address is the
  last bad byte, not the first (upstream; seen with printm of a forged
  pair).
- libdtrace: the userland struct/string 8-byte record issue from round 1
  is fixed in the current compiler build (u_struct/u_ustr now 16/256);
  the compiler never emits DIF_OP_ALLOCS, COPYS or RLD* (only crafted DIF
  reaches them).
- Design (from VMM helper): the hypercall ring gate is an exact DPL match,
  so rings 1 and 2 can call nothing (consistent today).

### Decisions still with the user

Guest-tagged scalar stores refused; ENABLE ENOMEM vs truncation for long
names; dist close on every consumer close; hypertrace_probe epoch trust /
si_cred (all unchanged, as instructed); dtrace_filterfind wire or remove.

## Method

`contrib/hypertrace/tests/coverage-kernel.py OUTPUT [--suite NAME] [--sanitize]`
compiles the ORIGINAL kernel source files, unmodified, as kernel translation
units: `-D_KERNEL -DKLD_MODULE`, the amd64 GENERIC `opt_global.h`
(INVARIANTS, WITNESS, QUEUE_MACRO_DEBUG_TRASH, SMP, KDTRACE_HOOKS ...;
recorded copy `tests/kcov/opt_global.GENERIC.h`), the tree's own headers and
generated `*_if.h`/`vnode_if*.h`.  They link against an audited shim
(`tests/kcov/khx_*.c`), run in userland, and are measured with LLVM
source-based coverage, so counters map to the real file paths and every
report uses the whole-file denominator.

Shim boundary (all in `tests/kcov`, excluded from production numbers):

- `khx_host.c` (userland): allocation with M_NOWAIT fault injection, tag
  accounting and poison-on-free; locks with owner tracking that panic on
  recursion, release by non-owner, destroy while held and cooperative
  deadlock; sleep/wakeup with an optional deterministic scheduler hook;
  expected-panic capture; per-thread `%gs` base so `curthread`/`PCPU_GET`
  work unchanged.
- `khx_kern.c` (kernel ABI): malloc(9), mutex(9)/sx(9) (incl. `mtx_assert`
  and `sx_assert` enforcement), condvar/sleep/sema, copyin/copyout with fault
  ranges, uiomove, devfs with per-cdev thread counts (destroy_dev waits),
  module/SYSINIT execution, smp_rendezvous accounting.
- `khx_virtio.c`: newbus device, VirtIO bus, split-virtqueue model (errno
  results, descriptor accounting, completion order, `virtqueue_drain` cursor
  and `enable_intr` coalescing as in `virtqueue.c`), taskqueue(9), coroutine
  kthreads stepped one sleep at a time.
- `khx_sysctl.c`: OID set, lookup and kern_sysctl.c handler contracts.
- libc-colliding kernel symbols are renamed in every kernel object
  (`llvm-objcopy --redefine-syms`); any unresolved kernel symbol not in an
  explicit identical-contract allowlist fails the build.

Branch reporting: `branches(all)` is LLVM's counted outcomes for the file,
including outcomes inside macro expansions (KASSERT, queue(3) debug checks,
the malloc(9) `__builtin_constant_p` folding, `do { } while (0)`), using the
lower of LLVM's file summary and its per-line records.  `branches(source)` are
the decisions written in the measured file.  Macro outcomes are listed by
class; none are dropped from `branches(all)`.

## Final results

Evidence: `/usr/obj/5BSD-hypertrace-validation/cov-kernel-final-20261021/`
(coverage, `summary.json`, `sources_unchanged: true`) and
`cov-kernel-final-sanitize-20261021/` (ASan+UBSan, all suites 0 failures).
`vmm_hypertrace` was built by a helper (see its section).  "Changed" is the
driver's changed-vs-HEAD view (lines added or modified by 5BSD; files new
since HEAD count every line).  Branches are the conservative
`branches(all)` (lower of LLVM summary and per-line records) and the
`source` branches written in the file.

| Suite / file | Lines (whole) | Branches all | Branches source | Functions | Changed lines | Changed branches | Changed functions |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| dttransport.c | 364/364 100% | 182/210 | 145/146 | 20/20 | 364/364 | 182/210 | 20/20 |
| virtio_dtrace.c | 1607/1632 98.5% | 1081/1195 | 1000/1034 | 50/51 | 1640/1665 98.5% | 1082/1182 | 50/51 |
| hypertrace.c | 507/524 96.8% | 298/344 | 290/312 | 30/30 | 510/527 96.8% | 298/324 | 30/30 |
| hypertrace_map.c | 144/144 100% | 75/100 | 67/68 | 8/8 | 146/146 | 75/82 | 8/8 |
| dtrace_ioctl.c | 737/791 93.2% | 304/444 | 261/296 | 2/2 | 231/234 98.7% | 113/128 | 1/1 |
| dtrace_load.c | 80/86 | 24/86 | 4/6 | 1/1 | 29/29 | 11/14 | 1/1 |
| dtrace_unload.c | 64/77 | 18/41 | 8/12 | 1/1 | 21/21 | 6/6 | 1/1 |
| amd64/dtrace_isa.c | 372/582 63.9% | 144/310 | 128/246 | 26/28 | 118/145 81.4% | 48/66 | 5/5 |
| dtrace_db.c (in dtrace_isa.c + dtrace_immstack.c) | 122/177 | 52/83 | 47/74 | 6/8 | 123/178 69.1% | 53/86 | 10/16 |
| dtrace_immstack.c (arm64/riscv code, built natively) | 57/72 79.2% | 32/36 | 32/36 | 1/1 | 57/72 | 32/36 | 1/1 |
| amd64/dtrace_vm_subr.c | 163/257 63.4% | 106/112 | 106/112 | 6/18 | 163/257 (new file) | 106/112 | 6/18 |
| dtrace.c | 8339/12742 65.4% | 4439/8977 | 3803/6406 | 211/284 | 3270/4112 79.5% | 1700/2574 66.0% | 113/130 |
| amd64/vmm/vmm.c | 731/2235 | 329/1205 | 280/964 | 47/131 | 305/305 100% | 170/180 | 25/25 |
| dev/vmm/vmm_dev.c | 332/1615 | 170/876 | 153/666 | 17/51 | 27/27 | 22/22 | 4/4 |
| amd64/vmm/x86.c | 66/389 | 41/198 | 41/178 | 2/5 | 6/6 | 0/0 | 1/1 |
| amd64/vmm/vmm_dev_machdep.c | 24/477 | 49/215 | 49/188 | 1/3 | 17/19 | 6/6 | 1/1 |

Also linked and reported, no 5BSD executable change: dtrace_sysctl.c (0/32,
SYSCTL declarations only), dtrace_anon.c, dtrace_modevent.c, dtrace_vtime.c,
dtrace_debug.c.  Header inlines (sys/hypertrace.h, hypertrace.h,
hypertrace_wire.h) are exercised through these units but not reported as
separate files.

Run sizes: dttransport 12203 checks (4 expected panics); virtio_dtrace
37498; dtrace_hypertrace 10594 (1 expected panic); dtrace_vm_subr 145;
vmm_hypertrace 592 (9 expected panics).

### dtrace_hypertrace suite (dtrace.c, hypertrace*.c, dtrace_ioctl.c, ...)

DIF is produced from D by the worktree libdtrace (coverage-compiler build)
in NODEV|NOSYS mode, linked with `hypertrace_link()` as dtrace(1) does
(`tests/kcov/dofgen.c`, one process per program; `vprog` emits the
guest-side forwarding program from `dtrace_vprog_from()`, `vsrc` the host
program after that rewrite).  169 programs (`dtrace-corpus.d`); 304 table
cases run in host and/or guest context (`t_dtrace_dif.inc`), each checked
against D-language results computed by hand for the given inputs (string
functions per the illumos/FreeBSD semantics, register numbers per
regs_x86.d, frame chains, page contents), plus 31 scenario cases
(`t_dtrace.c`, `t_dtrace_ht*.inc`, `t_dtrace_ioctl.inc`).  Guest firing
goes through `hypertrace_probe()` with a fake VM whose memory is reachable
only through the vmm_* callbacks (kernel window, user window, the last 256
bytes of the address space), with VMM failures injectable (EOPNOTSUPP,
EFAULT, missing routines, page-translation fallback).  The real amd64
`dtrace_isa.c` is linked: `dtrace_asm.S` primitives are emulated (the null
page and injected ranges fault), `dtrace_probe_error` is the assembly
routine verbatim, and stack walks run over the test's own frames.
immstack() symbolization uses private ELF symbol tables naming test
functions and a linker_file reached through kobj dispatch.

### dtrace_vm_subr suite (dtrace_gla2hva)

`t_vm_subr.c`: host "physical memory" is an arena behind a dense
vm_page_array and direct map; each case writes guest page tables (32-bit
with PSE, PAE with an unaligned PDPT, 4-level, LA57, flat) and EPT/RVI
nested tables, and expects the hand-computed host address (or EINVAL).

### vmm_hypertrace suite (built by a helper agent; summarized)

`t_vmm_ht.c`, `khx_vmm*.{c,h}`, `khx_vmm_stubs.c` (audited panic stubs for
unrelated VMM subsystems), `khx_vmm_cpu.h` (forced include routing
CPUID/CR/XCR0 and VMM spin locks to models).  Ten cases: module hook
install/withdraw under the config lock; VM identity allocate/release in
vm_create/vm_destroy/vm_reinit on every failure path; the DTrace-probe
hypercall through the real `vm_run` exit dispatch (oracle: the
`machine/bhyve_hypercall.h` ABI and SysV argument registers; page-straddling
argument blocks; all error returns); dispatch/permission table; backend
accessor KASSERTs (expected panics); the vmm_* accessors; the guest's own
`bhyve_hypercalls_enabled()` against `x86_emulate_cpuid` (bhyve and KVM
leaf layouts); the identity/attestation ioctls; `/dev/vmmctl` identity-checked
destroy including a deterministic reinit/destroy race.  Development runs
`cov-kernel-vmm-dev/`, final `cov-kernel-vmm-20261021/`,
`cov-kernel-vmm-sanitize-20261021/`.  No production defect found.

## Bugs found and fixed

1. `virtio_dtrace.c: vtdtr_drain_virtqueues` reused the RX `virtqueue_drain`
   cursor for the TX ring.  The RX loop leaves the cursor at the ring size,
   so the TX loop never ran and every TX control buffer still owned by the
   ring leaked at detach or failed attach (up to ring-size x ~2.2 KiB per
   detach).  Fix: reset the cursor (and use the API's `int` type).
   Regression: `detach-reclaims-tx` (fails before: 3 leaked `devbuf`
   allocations; passes after).  Evidence of the failing run:
   `cov-kernel-virtio-prefix-20261021/`.
2. `virtio_dtrace.c: vtdtr_attach` passed `NULL` as the kthread_add(9)
   format and the name as a stray variadic argument, so the communicator
   thread was named by kvprintf's "(fmt null)\n".  Fix: pass the name as the
   format.  Regression: `detach-reclaims-tx` thread-name check.

3. `sys/cddl/contrib/opensolaris/uts/common/sys/dtrace.h: dtrace_nextpow2`
   was a C99 `inline` definition in a header, which provides no external
   definition: at -O0 (or whenever the compiler declines to inline) the
   reference stays unresolved.  Fix: `static inline`.  Found when the
   unoptimized coverage build failed to link.
4. `dtrace.c: dtrace_dif_emulate` binary operators (OR, XOR, AND, SLL, SRL,
   SUB, ADD, MUL, SDIV, UDIV, SREM, UREM) asserted that at most one operand
   carried a VM handle.  On a virtual probe, every argument is tagged with
   that probe's handle, so `arg0 + arg1` panicked an INVARIANTS host
   (and on non-INVARIANTS kernels silently picked one handle).  Fix:
   `dtrace_vmhdl_merge()` keeps a handle common to both operands, and turns
   operands from two different VMs into ILLOP.  Regression: `d_arith` in
   guest context (panicked before: `cov-kernel-dtrace-prefix-20261021/
   run-vmhdl-assert.log`).
5. `dtrace.c: dtrace_probe` checked by-reference loads with
   `dtrace_vcanload` even for statements that store nothing (size 0), so a
   clause-local assignment of a guest string on a virtual probe raised
   BADADDR and dropped the clause.  Fix: skip the check for size-0
   records.  Regression: `d_search_err` guest case.
6. `dtrace.c: dtrace_guest_load` reported the address of any later guest
   load as the fault address once a fault was already pending, so
   `stringof(bad) == stringof(good)` on a virtual probe reported the good
   string's address in ERROR's arg5.  Host loads keep the first fault.
   Fix: return immediately when a fault is pending.  Regression:
   `f_strcmp` guest case (before: illval 0xffff800000100080, the valid
   string; `run-guest-illval-overwrite.log`).
7. VM identifiers from the caller were used as indexes into the
   1024-entry per-VM probe tables without a bound: a DOF probe description
   (`dofp_vmid`, 16 bits) in DTRACEIOC_ENABLE reached `dtrace_match()`
   (`dtrace_vprobes[]`, `dtrace_bymod[]`...), and DTRACEIOC_PROBES/
   PROBEMATCH indexed `dtrace_nvprobes[]`/`dtrace_vprobes[]` with
   `dtpd_vmid`.  Out-of-bounds kernel reads of adjacent statics, and a NULL
   or wild pointer dereference (host panic) for any caller that can open
   /dev/dtrace/dtrace.  Fix: `dtrace_dof_probedesc()` refuses
   `dofp_vmid >= HYPERTRACE_MAX_VMS` ("invalid probe VM identifier", ENABLE
   returns EINVAL) and the FreeBSD PROBES/PROBEMATCH ioctl returns EINVAL.
   Regression: `ioctl-bad-dof` VM-identifier block (UBSan before: "index
   1024 out of bounds for type 'int[1024]'" at dtrace_ioctl.c:808,
   `run-vmid-oob-sanitize.log`).  The illumos-only DTRACEIOC_PROBES copy in
   dtrace.c has the same pattern but is not compiled on FreeBSD; left as is.
8. `dtrace.c: dtrace_dist_unregister` freed the 64-byte name buffer with
   `strlen(name) + 1`.  Harmless with FreeBSD's SPL (size ignored) but it
   breaks the kmem_free(9F) contract the file follows elsewhere.  Fix: free
   `DTRACE_KONNAMELEN`.  Regression: `dist` case with the harness's strict
   kmem size check (before: "kmem_free size 6 != allocation 64",
   `run-dist-kmem-size.log`).
9. `dtrace.c: dtrace_immstack_cache` treated `dtrace_casptr()`'s return
   (the previous key) as a success flag: claiming an empty slot returned
   immediately without storing the name, so every PC needed two misses (two
   full symbol-table walks in probe context) before it was cached.  Fix:
   proceed only when the previous key was NULL.  Regression:
   `immstack-symbols` (cached frames are named after the symbol tables are
   removed; before: "??", `run-immstack-cache-and-uninit.log`).
10. `amd64/dtrace_isa.c: dtrace_populate_stack_str` read the uninitialized
   `off` when immstack caching is disabled (sysctl
   `dtrace_immstack_caching_enabled=0`); with stack garbage >= 0x10000 every
   frame printed "??" and no symbol lookup ran.  Fix: initialize to 0.
   Regression: `immstack-symbols` caching-disabled and module-symbol runs
   (before: all frames "??" and no linker lookup, same log).
   Pre-fix sources for 6-10: `cov-kernel-dtrace-prefix-20261021/
   dtrace.c.before-fix{3,4,5,6}`, `dtrace_ioctl.c.before`,
   `dtrace_isa.c.before`.

## Infeasible outcomes (kept in the denominators)

dttransport.c: `sc->dying` with `gsc != NULL` in `dtt_queue_enqueue_at` (both
are changed together under the exclusive transport lock).

virtio_dtrace.c (source-level, 35 outcomes): `vtdtr_init_rxq`/`init_txq`
errors (M_WAITOK taskqueue_create, constant 0); sglist_append failure (a
<= PAGE_SIZE buffer needs at most the two segments provided);
`length <= DTT_MAXDATALEN` (equal constants, already implied);
invariants of the stop/fresh state machine (session stop implies cleanup
pending; READY implies stopped+pending+applied until activation; cleanup
identity equals node identity while stopped; rekey and cleanup exclude each
other; fill_desc is never asked for READY while stopped or rekeyed);
defensive NULL checks unreachable through dttransport (`sc`, `e`,
`identity`); `node_epoch == 0` with a nonzero node id; probe list never
populated; TX has no taskqueue; dead helper `vtdtr_cq_count`.  Removing or
asserting these is a design decision for the user (see decisions).

Kernel-side infeasible outcomes added in this pass:

- hypertrace.c (17 lines): see checkpoint-1 list (reserved-provider race,
  UINT32_MAX reference count, map divergence, >1M registrations behind the
  256K global vprobe limit).
- dtrace_ioctl.c changed lines 484, 1037, 1090: the probe-list size check
  after a successful match (`ndesc > n_matched`), and two defensive
  branches behind earlier validation.  The `state == NULL` test after
  `devfs_get_cdevpriv()` is unreachable (every fd was opened by
  dtrace_open) and would read an uninitialized pointer (upstream code).
- dtrace_vm_subr.c: 12 helper functions are never called (the `dtrace_pml4e`
  .. `dtrace_pde_to_pte` family, the four index helpers,
  `dtrace_canonical_check`, `DTRACE_DMAP_TO_PHYS`: 93 lines); in the live
  functions only `dtrace_valid_bit`'s PT_X86/default arms (callers accept
  only EPT/RVI), the `pmap == NULL` test repeated after gla2hva's own check,
  and loop exits that cannot occur (every level returns).
- dtrace_db.c: `dtrace_linker_elf_search_symbol` and
  `dtrace_symbol_is_ambiguous` are never called (34 lines); fault branches
  need a kernel fault while reading a symbol table.
- dtrace_immstack.c: fault branches (kernel fault while reading symbols) and
  the final offset-room check (unreachable for 8-byte-multiple slots).
- dtrace_isa.c: misaligned record buffers (records are aligned), fault
  branches, size < 3 slots (excluded by the earlier size check).
- DIF_OP_HYPERCALL frame count above HYPERTRACE_STACK_MAX_FRAMES: refused by
  the DIF validator first (tested), so the interpreter check is defensive.

## Remaining gaps to 97% (dtrace.c changed lines: 3270/4112, 842 open)

Heuristic classification of the open changed lines (by the condition that
guards them; exact line list in `summary.json` `patch.uncovered_lines`):

| Class | Lines | Status |
| --- | ---: | --- |
| VM-tag mismatch / tagged value on a host probe | ~141 | infeasible by construction: only a virtual probe's own handle can appear, and tagged scalars cannot be stored |
| Dead functions (no caller): dtrace_condense, dtrace_addrxlate, dtrace_vmloadmem, dtrace_virt_state_tick (`virt_state` is never set), dtrace_strcmp, dtrace_filterfind | 93 | infeasible; removal is a decision |
| Address-arithmetic overflow guards beyond what the top-of-address-space window reaches | ~50 | mostly defensive |
| Privilege denied (FreeBSD's `dtrace_cred2priv` grants all) | ~35 | infeasible on FreeBSD |
| Allocation failures, diagnostics, invariant panics | ~31 | partly reachable with fault injection, not done |
| Other | ~490 | reachable but not exercised: chiefly dif_subr/dif_emulate error returns (≈180), dynamic-variable dirty/rinse drops, vprobe-space teardown edge cases, guest stack helpers' remaining failure orders, privilege-free immstack/printimmstack variants |

The open "other" lines are the work needed to reach 97%; none of them was
found to hide a defect class not already tested elsewhere.

## Findings not fixed (owners / decisions)

libdtrace (owner: libdtrace agent; not edited):
- `huregs[0]` segfaults the compiler; the HyperTrace linker keeps
  process-global state across dtrace handles; an undeclared `self->`
  variable aborts in NODEV mode.
- A dereferenced userland struct or string (`*(userland struct s *)p`,
  `*(userland string *)p`) is given an 8-byte record; kernel structs get
  their full size.
- `this->s = *(struct s *)p` fails HyperTrace link typing ("type mismatch in
  variable store"), so struct-by-value copies (DIF_OP_COPYS) cannot be
  tested.
- `dtrace_vprog_from()` emits one forwarding statement per action, so a
  clause with N actions makes N hypercalls per firing.

Upstream FreeBSD code (reported only):
- `rw_write_held`, `rw_iswriter`, `sx_exclusive_held`, `sx_isexclusive` load
  a pointer from their argument and treat it as the lock, unlike
  `rw_read_held`/`sx_shared_held`/`mutex_*`; given a lock address they read
  `lo_name` as a lock object.
- `bcopy()`/`copyinto()` report `regs[rd]` instead of the destination as the
  fault address.

Design questions (5BSD):
1. Guest probe arguments and variables carry the VM handle and scalar
   stores refuse tagged values: `g = arg0`, `self->x = arg0`, `*p = arg0`
   (alloca) all raise ILLOP on a virtual probe.  Intended?
2. ENABLE's probe-description list fails with ENOMEM when a provider's
   probe name exceeds a description field (e.g. a function name >191
   bytes) instead of truncating as DTRACEIOC_PROBES does.
3. The dist KPI calls every dist's `dtdops_close` on every consumer close,
   whether or not it was opened for that state.
4. Dead code listed above (dtrace.c, dtrace_vm_subr.c, dtrace_db.c): remove
   or wire up?
5. `hypertrace_probe()` trusts the VMM-supplied handle epoch; `dtrace_open`
   uses `si_cred` as upstream does.
6. From the VMM helper: HYPERCALL_TEST is callable from guest ring 3 and
   printf()s a guest-chosen value (console flooding); `hw.vmm.hv_mode` is
   RDTUN and its handler maps any write to BHYVE_MODE; `hypercall_copy_arg`'s
   `arg_len` checks are unreachable from current callers.
7. Checkpoint-1 virtio/dttransport invariants (remove or assert).

## Live-only (not measurable offline; needs the VM gate)

- Real VMX/SVM exits (`vmx.c` EXIT_REASON_VMCALL hunk, `svm.c` VMMCALL
  intercept and `svm_handle_hypercall`), real EPT walks and
  `vm_gla2gpa`/`vm_gpa_hold`, guest entry and FPU/XCR0 switching.
- The virtio transport against a real host daemon and device; module
  load/unload with real fbt/sdt providers and invop trap frames; DTrace's
  kernel fault handler for arbitrary bad kernel addresses (the harness only
  faults the first page and injected ranges); cross-calls on real CPUs;
  arm64/riscv builds of dtrace_isa.c and the arm64/riscv VMM hooks (only
  their portable dtrace_immstack.c was built here); KMSAN.

## Build frontend (AGENTS.md)

No change to build inputs, staging, signing, packaging or publication:
the fixes are source-level kernel fixes in existing files and the rest is
test code under contrib/hypertrace/tests.  No `/usr/src` or `build-bsd`
change is needed or was made.
