# bsdtrace review — findings status

2026-08-16.  Three independent reviews (libipt usage vs ptxed and
simple-pt; HWT ioctl protocol vs sys/dev/hwt + sys/amd64/pt; an
adversarial bug hunt) followed by a full fix campaign and
adversarial verification rounds.

The core was verified CORRECT from the start: HWT ioctl
ordering/ABI (static asserts in bsdtrace.h), buffer-offset
encoding, post-stop XSAVE offset reads, libipt event-drain
placement, pt_config setup, image section offsets, and ELF
load-bias math for the standard paths.

## Fixed (first pass, 2026-08-16)

Kernel: MUNMAP record addr copyout; uninitialized baseaddr infoleak
in the vfs_vnops MMAP hook.

bsdtrace: wrapped-ToPA-ring un-rotation at snapshot (primary and
per-thread); BUFFER-record demux by buf_id; pause-on-mmap wakeup
broadcast + per-poll re-wake; exec -T <n> normalization; exec
SIGINT/SIGTERM handler + finalize-failure exit propagation +
reaped-child kill guard; per-thread snapshots survive an empty
primary buffer; trace-mode zombie detection; SIG_DFL restore before
finalize; decode-loop robustness (event-error resync, pts_eos,
sync retry with progress guard); collapsed-stack OOB write; PLT
call latch; depth-cap balancing; entry_tsc consumption; lost-MTC/CYC
counter accounting; callers <root> exclusion; 64-bit counters;
parse_size validation; -r inverted range rejection; ELF strtab
bounds + sh_entsize validation; KERNEL sections preserved across
exec; MUNMAP section removal; meta timing clamps; meta fclose
warning; trace-mode slide from the executable PT_LOAD.

## Fixed (second pass, 2026-08-16)

- Capture-environment meta records ("capture_env" + "addr_range"):
  CPU identity, CPUID 0x15 TSC/CTC ratio, nominal frequency
  (MSR_PLATFORM_INFO via cpuctl, CPUID 0x16 fallback), and the
  hardware address-filter setup are recorded at capture and replayed
  into pt_config at decode (live, offline, and per-thread sidecars).
  This revives MTC timing, enables CBR-based CYC calibration, makes
  cross-machine errata correct, and arms the SKL014 filter
  workaround.  Absent records fall back to the local CPU with a
  note.
- Kernel MMAP records now carry pgoff/len (hwt_record ABI extension,
  all producers initialize them); bsdtrace consumes them end-to-end
  (records, sidecar "pgoff"/"len" fields with legacy fallback,
  seeded sections from kve_offset) and elf.c biases mappings by
  matching the executable PT_LOAD at that file offset — exact for
  nonstandard (JIT/plugin) mappings.
- Tracing-gap handling: enabled/resumed/disabled events are emitted
  in text/JSON and reset the flow trackers; overflow and non-resumed
  enables also clear the shadow stacks.
- ptev_async_branch interrupt markers: IRETs no longer pop
  legitimate frames in -K traces.
- Per-activation timing: recursion no longer zeroes outer
  activations (calltree slot array + profile activation stack).
- FARCALL/FARRET labels replace SYSCALL/SYSRET (int3/IRET honesty).
- Alloc robustness across decode.c aggregation modes and -F/-T/-m
  option parsing; duplicate options free their prior allocation.
- Option parsing uses strtol/strtod with full validation everywhere
  (garbage, trailing junk, ranges, -T list truncation warning).
- exec PATH resolution matches execvp (empty component = cwd,
  _PATH_DEFPATH fallback, S_ISREG + access(X_OK)).
- JSON: bytes >= 0x80 escaped (always-valid output); fmt buffers
  sized for full escape expansion; dead functions removed.
- .meta: paths unescaped on read; MAXPATHLEN static assert;
  capacity growth capped; extended records parse with legacy
  fallback.
- STT_GNU_IFUNC: symbolized best-effort; -r on an ifunc fails with
  an explanatory error instead of programming the resolver stub;
  both .symtab and .dynsym are scanned.
- DWARF: end_sequence rows bound attribution (no cross-CU stale
  rows); ERROR vs NO_ENTRY distinguished where it matters (this
  libdwarf is elftoolchain — by-value Dwarf_Error, no dealloc
  needed); cache keyed by (path, slide); rows require both file and
  line to resolve.
- Size-0 symbols bounded by the sorted-table successor; same-address
  aliases resolved by descending-size tie-break + tie-walk.
- kve_structsize bounds guards in the VMMAP walks.


## Verification loop (2026-08-16, three rounds)

Round 1 (regression hunt on fix interactions + fresh-eyes review of
the churned files) found and fixed: a genuine interaction regression
where the disable-event state reset broke shadow-stack balance across
resumed context switches (the reset was removed — resumed enables
continue contiguous flow); the meta reader's exec handling wiping
kernel sections (an earlier fix that had silently failed to apply);
the wrap-rotation seam trusting the stale periodic-record fallback
(now only a directly-reported stop position rotates; otherwise the
snapshot is saved unrotated with a warning); reader/writer sizing for
escaped paths; the sysctl-fallback kernel section now reaching the
primary sidecar; a munmap addr==0 parity guard; speedscope phase-2
frame lookups no longer minting frames after the frame table was
emitted; calltree push-failure balancing; SIG_DFL restored before the
blocking reap; CPUID 0x16 nominal-frequency rounding.

Round 2 (hostile maintainer pass over the round-1 fixes) found and
fixed: an off-by-one strncmp that made the new unparsable-record
warning dead code (now sizeof-based); a silent-degradation hole when
rotation buffer allocation fails (the non-rotated fallback is now a
single shared path that always warns on an unrotated wrapped ring);
the dead flow_reset parameter and its contradictory comment; a
truncation warning for over-long sidecar paths; a documented caveat
on the push_overflow counter.  Tests were added for the warning and
the corrupt-meta case was refreshed to current record formats.

Round 3 (confirmation pass) verified all round-2 fixes correct,
proved the remaining seam edge case unreachable, and reported CLEAN.


## Correctness review of all converted components (2026-08-16, round 4)

A dedicated correctness pass over every component converted from
ObservableBSD (libotelexport, bsdinstruments, hwtlm, and a fresh
Intel-PT-focused look at bsdtrace + the pt kernel backend).

Fixed:
- bsdinstruments watch.c: quantize POSITIVE bucket bounds were
  exported one power of two low (the bucket label — its lower bound —
  was passed as the inclusive upper; negative/zero buckets were
  coincidentally right); llquantize step buckets had the same
  label-as-upper bug; stack()/ustack()/sym()/mod() aggregation keys
  were memcpy'd as raw pointer bytes (now dispatched by record
  ACTION like dtrace(1): kernel stacks symbolized via
  dtrace_lookup_by_addr, user stacks as pid+hex frames);
  normalize() (dtada_normal) is now applied to every exported
  value; a final dtrace_work() after dtrace_stop() recovers
  END-probe output and the last buffer; lquantize/quantize record
  sizes validated; stddev computed exactly in 128-bit where
  available; sub-8-byte keys print unsigned (dtrace(1) parity);
  string keys no longer truncate (growable buffers); the lquantize
  underflow bound is computed in 64-bit.
- hwtlm: the DRM sysctl reader type-sniffed by returned length,
  misreading common string values ("300" MHz -> 3158067) — now
  string-parsed like the Swift original; exec resamples RAPL
  counters every ~30 s so 32-bit counter wraps no longer lose
  65536 J chunks on long runs; watch exits 1 on a mid-run RAPL
  failure; interval/duration parsing rejects NaN/garbage/overflow;
  per-core JSON escapes C-state names.
- libotelexport: bytes >= 0x80 are JSON-escaped (arbitrary DTrace
  bytes could previously emit invalid JSON and poison a whole OTLP
  batch); drop counts survive flush cycles with no log records
  (aggregation-only profiles never reported drops); zero-bucket
  histogram datapoints are skipped (OTLP shape invariant);
  timestamps are UTC with 'Z' (Swift parity, lexical
  comparability); partial_success parsing tolerates whitespace.
- bsdtrace/PT: the hardware IP filter now programs INCLUSIVE range
  ends — IA32_RTIT_ADDRn_B is inclusive per the SDM, so the
  previous exclusive end included the first byte of the adjacent
  function; in TraceStop mode any call to that neighbor silently
  killed the rest of the trace.  The sidecar and decode-side filter
  stay consistent automatically.  pgoff-based mapping bias now
  matches by file-range coverage (whole-file PROT_EXEC and JIT
  mappings bias correctly); the interpreter range label uses the
  real PT_INTERP basename.

Documented limitations added (verified rare, fixes disproportionate):
- Two simultaneous live mappings of the same binary (dlopen of
  argv[0], fdlopen double-maps) keep only the lower mapping in the
  image; sequential remaps (dlclose/reopen, re-exec) are correct.


## Kernel PT backend review (2026-08-16, round 4)

A dedicated correctness review of the pre-existing (upstreamed) Intel
PT kernel backend surfaced real defects — NOT introduced by the
Swift->C conversion, but fixed here:
- pt.c: the ToPA table was mallocarray'd, so it was neither
  4K-aligned (below 64KB) nor physically contiguous (above it), yet
  the CPU walks ToPA entries by physical address and the table base
  must be 4K-aligned — the default 64MB buffer silently corrupted
  memory on buffer wrap.  Now contigmalloc(9)'d, page-aligned and
  contiguous, failing cleanly if the allocation is impossible.
- pt.c: HWT_IOC_STOP (pt_cpu_stop_clean) clears TraceEn but leaves
  the context set, so the following close -> disable -> pt_cpu_stop
  hit KASSERT(TraceEn != 0) — a deterministic panic on the normal
  stop-then-close path (and a clobbered final offset without
  INVARIANTS).  pt_cpu_stop now no-ops when PT is already stopped.
- pt.c: the "wait for the NMI handler to exit" barrier used
  atomic_cmpset, which cleared the flag and returned instead of
  waiting; it now spin-waits on the flag.
- pt.c: pt_topa_status_clear did a no-op read-modify-write of a
  write-1-to-clear MSR; now writes the single reset bit.
- hwt_backend.c: hwt_backend_svc_buf called the backend op through a
  NULL pointer (PT implements no svc_buf); now returns EOPNOTSUPP,
  matching the thread_alloc/thread_free NULL guards.

**Reinstall note:** these change hwt.ko and pt.ko; reinstall both
with the matching bsdtrace.  Rebuilt modules staged in
~/pkgs-observability/modules/.

Deferred to a maintainer with PT hardware (needs live validation, and
the only real fix enqueues a record from NMI context — the exact
thing the deferred-SWI design avoids):
- pt.c: a ToPA overflow (data-loss) signal set in the NMI but
  consumed in the deferred SWI can be dropped if teardown nulls the
  context in between; intermediate buffer-boundary records can also
  coalesce under a fast producer.  Each buffer record carries an
  absolute offset so decode position stays correct; only the
  discrete overflow-warning can be lost.

## Qualification re-run (2026-08-22, no-root tier)

Fresh rebuild of all four components (bsdtrace, bsdinstruments,
hwtlm, libotelexport) from clean bmake: no warnings, no breakage.
Everything runnable without root re-passed; NO new defects found.

- ATF suites (run standalone, per-case result files): libotelexport
  11/11, bsdtrace 12/12 + 1 skip (bsdtrace_ptwrite.h not installed
  in the session jail), hwtlm 10/10, bsdinstruments 10/10.
- ~/ObservableBSD test-bsdtrace.sh against the BASE binary:
  18 pass / 0 fail / 84 skipped (root + live-PT tier).
- bsdinstruments: full sweep of all 236 profiles through
  `generate` (params supplied where declared) — 236/236 produce
  non-empty D.  All 236 fed to `dtrace -Z -e`: 195 compile clean
  even with /dev/dtrace unavailable in the jail; the 41 failures
  are all environmental (pid provider needs the device+root; args[]
  on SDT probes cannot be typed while the probe is invisible) —
  re-run the same loop as root on the host to close them out.
- hwtlm: list (text + valid JSON), watch text/JSON-lines/per-core,
  exec exit-code propagation, and --format otel end-to-end into a
  local OTLP/HTTP sink (gzip, valid JSON, per-core dataPoints carry
  cpu_id attributes).
- libotelexport OTLP pipeline re-proven with a C driver against a
  local sink: logs (attrs incl. one-shot drops counter), sum
  metrics, histogram (bucketCounts/explicitBounds arity correct),
  gzip content-encoding — all valid OTLP JSON.
- bsdtrace offline decode exercised on synthetic PSB/TIP streams:
  syncs, maps images (EXEC record addr is the relocation slide),
  applies symbol slide, and error-paths stay clean across
  text/json/profile/tree/collapsed/callers/speedscope (speedscope
  output validates against its schema URL).  Fully faithful
  packet streams need real hardware; live decode remains in the
  root tier.

## Known limitations (documented, not defects)

- A .meta path containing a literal '"' cannot round-trip through
  the sscanf-based reader; such records are skipped with a warning
  (fixing needs a real tokenizer).
- decode_pt_probe's exec-hit accounting compares binary basenames,
  so same-basename different-path binaries alias in the snapshot
  length heuristic (affects only extent selection, not decode).
- JSON output escapes non-ASCII as latin-1 \u00XX (lossy for UTF-8
  symbol names, but always-valid JSON).
- dwarf_addr_to_line is O(CUs x rows) per lookup; fine for profile
  (once per function), slow if ever used per-instruction.
