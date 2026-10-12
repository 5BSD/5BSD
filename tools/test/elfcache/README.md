# ELF cache validation

`vm.py` boots a disposable UFS snapshot with `vm_probe.c` as PID 1. It reads
an existing NO_ROOT stage and substitutes a test kernel and loader. It does
not install files on the host or publish a package repository. The work
directory must be new and under `/usr/obj`.

The probe owns an authority issuer only because it is the guest's PID 1.
It tests cache preparation, publication, directory identity, descriptor
permissions, private mappings, W^X, rejection of writes to pinned files, and
retention of that pin through the last unmap. It then launches 24 processes
with separate bootstrap pipes, using BSD, channel, and FIDL shared libraries.
The worker executable preserves and checks separate writable process state.
A separate child executes with the cache published, calls `closefrom(3)`, fills
those descriptor numbers with unrelated files, and repeatedly loads a new
cached library. It checks the function's actual cache-backed mapping, its
return value, unchanged application descriptors, and absence of descriptor
leaks over 100 load/unload cycles, including a library deliberately omitted
from the cache to exercise descriptor cleanup on misses.
This is a kernel/loader test, not a replacement for full Capsule/SwitchBoard
and real capability-channel tests.

Build a matching current world and test kernel first. In particular, the
host's installed syscall headers can differ from the source kernel. The
probe uses the object tree's staged headers. The loader must also have been
built with matching headers. A complete `buildworld` is the normal way to
obtain consistent components.

```sh
python3.12 tools/test/elfcache/vm.py \
  --stage /usr/obj/path/to/NO_ROOT-stage \
  --objtop /usr/obj/usr/src/amd64.amd64 \
  --work /usr/obj/usr/src/cache-vm-new
```

The configured test kernel is currently expected at `sys/CACHE-TEST/kernel`
in the object tree. `--kernel` and `--headers` select explicit matching
artifacts for component diagnosis; they do not establish a clean-world pass.
`--dry-run` builds the image without booting it.
`--qemu` selects the emulator; the default is the local patched QEMU used by
the capability test harness. A deadline terminates only that probe VM.
The run preserves a serial log, build log, object hashes, configuration,
and measurement records. `command.json` preserves the emulator arguments;
`host-load.jsonl` samples host load throughout execution, including exit status.
A pre-run load average alone cannot establish a quiet measurement interval. The cache used by this isolated kernel probe is
unsigned: the probe itself is the trust anchor. Signed activation is tested
separately through SwitchBoard, and must not be inferred from this probe.

Interpret the measurements carefully:

- Round zero includes startup and observer warm-up. Subsequent rounds
  alternate which mode runs first, with two warm pairs in each order. The
  measurement report records actual trial order, including fixed-order older
  captures. Use subsequent rounds for warm comparisons; separate fresh boots are needed for cold comparisons.
- `anonymous_object_growth_pages` is the change in system anonymous-object
  residency while workers exist. It includes observer effects; it is not a
  per-process private-RSS counter.
- `unique_object_growth_pages` and `total_unique_object_pages` count each VM
  object once. File-cache residency and the observer can change between
  snapshots. `cache_backing_pages` reports the cache's own resident pages.
- The cache backing file exists in both modes in this API probe. Consequently
  per-batch deltas do not measure the cost of retaining the cache itself.
- `summed_resident_pages` repeats shared mappings and is not physical memory.
  Never sum `kve_private_resident`: that interface reports whole-object counts
  for some mappings and repeats them when cache slices share a VM object.
- `CPU` records report accumulated guest worker CPU use. Wall time is sensitive
  to host contention, emulator scheduling, and guest clock calibration. Run
  performance comparisons after compilation and other controlled loads finish.

A completed run requires `ELFCACHE_VM_END failures=0`, including observed
cache mappings in every cache-mode worker. The initial v1 implementation
compares source bytes before substituting signed cached bytes and retains
private relocations. Ordinary ELF text is already shared by the VM. Packing
libraries alone does not establish a memory or startup saving; report measured
regressions as regressions.

## Coverage and cache inspection

`audit.py --root STAGE --cache CACHE --output report.json` reads ELF metadata
without executing staged programs. It checks every DT_NEEDED edge in BSD
program/library trees and capability bundles, so indirect dependencies and
plugin dependencies are included. It compares staged library bytes with cache
entry digests and separately reports runtime module candidates outside the
cache, custom search paths, resolution errors, and unreferenced entries.
Absolute symlinks resolve within the staged root. It does not emulate libmap,
loader hints or dynamically computed module names, establish signature trust,
or prove that a candidate passes the loader's eligibility checks.

The first staged-world audit found 4,224 covered edges in 1,536 ELF objects,
including 20 capability objects, with 170 referenced entries among 481 names.
This stage predates the current full-world rebuild; it is preliminary coverage,
not release evidence. Common direct dependencies included libc, libutil,
libthr, libm, terminal support, crypto, C++ runtimes, compression and libservice.
The cache contains FIDL, channel, capability-client and service dependencies.
Locale, GEOM, Lua and other modules in subdirectories require workload review.

```sh
elfcache build -r stage -l reviewed-libraries.txt -k private.pem -o cache
elfcache list cache
elfcache map cache
elfcache map -j cache
elfcache info cache
elfcache info -j cache
elfcache verify -j -p public.pem cache
elfcache verify -p public.pem cache
elfcache extract -p public.pem -o new-directory cache
```

JSON summaries (`info -j` and `verify -j`) use schema
`org.5bsd.elfcache.summary.v1` and explicitly report authentication and payload
digest verification. Structural inspection reports both as false. Verification
authenticates a private snapshot before reporting true; it emits no JSON object
on failure. Counts and byte totals describe storage, not physical memory.

`map -j` emits `org.5bsd.elfcache.images.v1` with payload hashes, file offsets,
source/payload sizes and canonical alias indexes. It is structural inspection,
so its authentication and digest-verification flags remain false. Path strings
use byte-values encoding (non-ASCII bytes become U+00xx); offsets refer to the
cache file, not runtime virtual addresses. Every index record is validated
before emitting JSON.

Extraction authenticates a private snapshot and all payload hashes before
creating the destination. It reconstructs unsigned ELF payloads and hashes each output. Format v2
excludes each source library's signature/policy container; extraction cannot
reproduce that removed signature. Aliases become separate read-only regular files, not reconstructed
symlinks. Existing destinations are refused. Inspection/statistics alone do
not authenticate an artifact, and extraction does not install it.

## Loader and script instrumentation

Build a dedicated VM world or loader with `RTLD_CACHE_PROFILE=yes`. The option
applies to the common rtld sources used for native and compatibility loaders.
The ordinary production build emits no profiling records or profiling clocks.
The shared load path covers startup/transitive dependencies and new mappings
from dlopen/fdlopen, including descriptor-granted library directories. It does
not instrument an unrelated foreign dynamic linker or count a dlopen that
merely reuses an already mapped object.

The maintained profiles are in the `bsdinstruments` catalogue:

```sh
bsdinstruments watch loader-libraries --duration 30 > loads.tsv 2> loads.errors
bsdinstruments watch loader-summary --duration 30 --format json > summary.json
bsdinstruments watch script-exec --duration 30 > execs.txt
python3.12 tools/test/elfcache/profile.py loads.tsv --output ranked.json \
  --collector-errors loads.errors --library-list candidates.txt --min-programs 2
```

The candidate list contains only observed absolute /lib and /usr/lib paths.
Candidate selection requires the saved, empty collector stderr file and exactly
one matching pair of capture markers. Concatenated captures are rejected, and
rows missing executable-start markers are excluded from automatic selection.
Review descriptor-relative names and dependency closure before using it; it
is not an automatic system policy or a claim of universal workload coverage.

`loader-libraries` emits versioned bounded records; `loader-summary` produces
aggregations usable through the existing text/JSON/OTEL exporters. Fields
include size, lookup time, cache-check time, map/dynamic-metadata time, requested
name, caller, and cache outcome. Outcomes 0..7 are outside cache directories,
cache unavailable, not listed, size changed, mmap failed, ineligible ELF,
bytes changed, and hit. Flags identify exec markers, dynamic loading, mapping
failure, truncated names, descriptor-relative paths, and failed clocks.
No descriptor numbers, pointers, service-handle contents, argv or environment
values are recorded. Version 2 includes source device/inode identity and size,
so descriptor-relative and absolute paths to the same file can be grouped within
one quiescent VM capture. This identity is not cryptographic and must not be
combined across boots or filesystem generations. Descriptor-only observations
still need resolution against the workload's signed generation inventory.

The collector observes utrace syscall entry globally via DTrace. It does not
set ktrace/ptrace flags, which intentionally prevent authority acquisition.
Use the existing authorized BSDTrace/DTrace access path. For a caller with
an authorized service connection and an explicitly allowlisted BSDTrace client
label, `bsdinstruments watch --broker loader-libraries --duration 30` uses the
delegated consumer descriptor. `probes --broker --provider capimage` queries the
kernel verification probes through the same path. A rejected broker request
never falls back to local device access; these options do not grant a client
tracing authority. The `image-verification` profile separates kernel exec,
verified-open, descriptor and mmap verification costs; it does not measure
userland signing or bundle checks. Do not disable
capability checks to collect a profile. These user-generated events are
untrusted diagnostics, never authority or signature evidence. Verify live
collection and descriptor-based launches in the VM before relying on a capture.

`script-exec` correlates attempted script paths (including shebang launches)
with exec outcomes and interpreter process names. Library events then describe
the interpreter's native libraries and runtime-loaded native modules. A sourced
shell script or a file passed to an already-running interpreter is not a new
exec; this profile cannot claim to identify all evaluated source files. Use the
existing Python/Node language probes for language-level activity where those
runtimes provide them. Match captures by guest timestamp and PID.

Start capture before the workload, preserve stderr, and reject captures with
DTrace errors/drops or missing start/end markers. Cover boot, daemon activation,
CLI tools, networking, filesystem operations, locales, authentication, and
script workloads. Rank distinct consumers/processes as well as load counts;
a tight shell loop must not be mistaken for broad system use. Profile timings
include observer overhead and exclude relocation/constructors; measure final
performance again with an uninstrumented loader.

`python3.12 -B tools/test/elfcache/tools_test.py` tests ranking and staged path
resolution. Native ATF tests cover the record ABI, bounded strings and errno.

## Signed system deployment

`tools/test/capimage/signed-system.sh` is a read-only guest check for a full
signed, plane-on stage with production capability-device isolation. Set
`ISOLATION_ENFORCE=1` and supply it as `EXTRA_SCRIPT` to a frozen copy of
`tools/build/fuchsia/vm-provider.sh`, after building and staging matching world,
kernel and modules. Finalize the unpublished stage with
`tools/build/capimage/sign-stage.sh -c -e` and a test key before making the VM
image. Keep the private key outside the stage.

The provider runner first checks that Capsule, SwitchBoard and core providers
are running and exercises BSDTime through the broker. The extra script then
requires the signature-enforcement marker, verifies every system bundle and
unit image against the guest trust catalogue, checks that external Unit.ucl
files are absent, authenticates the cache, and requires executable cache-backed mappings
in live BSDTime, BSDNetwork and BSDLog processes through
`switchboardctl cache-status`. The launcher queries its protected children
using its existing authority and returns only counters. Direct root
`procstat -v` is insufficient: protected VM-map access may be denied while
procstat still exits successfully with only a header. Success ends with
`SIGNED_SYSTEM_END`; an earlier partial log is not a pass. This complements
the synthetic kernel/loader probe and does not replace its pin-lifetime tests.

Use suites `lib/libcapimage usr.sbin/capsign usr.sbin/elfcache` for signing
and cache regressions in that guest. General unsigned-bundle parser tests
need a separate guest without the global require-signatures marker; rejection
of those unsigned fixtures under enforcement is intentional. Host tests of
new world libraries also require matching libc and loader ABIs, so running
new object-tree libraries against an older host is not deployment evidence.

Snapshot shell helpers before starting a long VM or stage operation. Editing
an executing shell script can invalidate the shell's buffered read offsets.

`measure.py RUN_DIRECTORY --output comparison.json` validates complete paired
VM measurements and writes medians plus every retained pair and run provenance.
It excludes round zero by default and requires at least three remaining pairs.
Ratios greater than one show startup/CPU regressions; positive residency-growth
differences show more observed growth in cache mode. Summed RSS is deliberately
excluded. The report carries the host load and interpretation limits; it is
not evidence of statistical significance or cold-start savings. Existing
output files are not overwritten. Run `python3.12 tools_test.py` for parser,
ranking, path-resolution and measurement-report regression coverage.

### Embedded signatures and veriexec integration (in progress)

The on-disk ELF signature ABI is shared through `sys/sys/capimage.h`.
`MAC_VERIEXEC_CAPIMAGE`, selected by amd64 GENERIC, adds an integrity check to
veriexec's executable hook independently of its enrolled fingerprint database.
The first implementation hashes the complete signed file under the vnode lock
and checks its Ed25519 signature. It checks the executable passed to `execve`
or `fexecve`; native ELF interpreter loading also calls `exec_check_permissions`.
The existing `O_VERIFY` open path and veriexec descriptor-check syscall also
perform this integrity check. Existing enrolled-fingerprint policy still runs
afterward and may be stricter.
Unsigned images remain subject to ordinary execution permissions and any
existing enrollment policy.

This check deliberately does not treat possession of a signing key as authority.
An otherwise valid signature made by an unknown key can establish byte integrity
for ordinary execution, while SwitchBoard still requires its trusted signer
catalogue and authenticated bundle/policy before granting capabilities. The
kernel does not parse UCL or nested bundle inventories.

`usr.sbin/capsign/veriexec_test:exec_integrity` exercises direct and descriptor
execution, unsigned and deliberately stripped programs, an ephemeral signer,
`O_VERIFY` opens and descriptor checks, modified ELF bytes,
policy/key/signature/header/footer metadata, and shebang
interpreter checks. It requires `kern.features.veriexec_capimage=1`; a skip on
an older host is not proof of kernel enforcement. Run it in the newly built VM.

This is not yet complete executable-integrity coverage. The remaining gates
include executable file mappings and transitions through `mprotect`, cache
payload identity, reliable recognition of damaged signature locators, and
post-verification mutation/race tests. In particular, a missing canonical EOF
marker is currently classified as unsigned; detecting damaged locators needs
additional format work. A policy that permits unsigned code also needs a
separate identity requirement where removing a signature must not be accepted.
Signed capability bundles already require their signed images. Do not describe
the current exec hook alone as complete system-wide signature enforcement.

Build matching world objects with `make -j$(sysctl -n hw.ncpu) buildworld
WITH_CLEAN=yes WITH_MALLOC_PRODUCTION=yes` when crossing libc structure ABI
changes. This tree defaults to retaining objects; omitting `WITHOUT_CLEAN`
alone does not request a clean build. A stale verifier built for the older FTSENT layout can link against
new libc yet read the wrong `fts_info` offset; a successful incremental link
does not prove runtime ABI compatibility. The signed-system boot gate must pass
with the exact staged libraries and kernel.

Signed cache sources additionally use
`MAC_VERIEXEC_CHECK_CAPIMAGE_FD_SYSCALL`. Unlike the ordinary descriptor check,
this operation requires a present, valid embedded signature. The authenticated
cache index records source and payload sizes, so a signed source cannot lose
its trailer and be reclassified as unsigned on this path. The loader treats
verification failure (including an unsupported kernel API) as a load error,
not a cache miss, and emits `source-signature-failed` in profiling captures.
The only MAC syscall operation exposed in capability mode is this descriptor
check; the dispatcher rejects other policy names and operations, and the
verifier requires `CAP_READ` on the existing descriptor. This does not expose
pathname lookup or policy mutation to sandboxed callers. The regression helper
checks valid verification, rejected legacy/other-policy calls, and rejection
after removing descriptor read authority. These changes require a matching
new kernel and loader and still await the corresponding VM gate.

The cache-only regression includes two identical fixture names in the cache,
then excludes their separate files from the disposable image. Before publication,
loading the missing library must fail. After publication a fresh executable must
load it, confirm its actual cache-backed function mapping, reuse one object for
both aliases, preserve private writable state across fork, and survive 100
load/unload cycles while application descriptor numbers are occupied. These are
loader/kernel acceptance checks, not proof of safe production library removal,
full service-channel isolation, or net memory savings. The fixture is never
removed from the host or the input stage.

The isolated VM defaults to 2 vCPUs and 2048 MiB. Override with `--cpus`
and `--memory-mb`; both values are recorded in `run.json`. Use identical
settings for compared arms. Cache-only lookup must also fail after issuer
revocation; this does not require already mapped code to be unmapped.

Use `--dry-run` to prepare an image and record its SHA-256, then use
`--run-prepared` with the same `--stage`, `--work`, `--cpus`, and `--memory-mb`
to execute it. The runner rejects image, stage, resource or emulator-version
mismatches and never overwrites an existing execution record. Older prepared
images without a digest must be prepared again. `prepared_test.py` exercises
refusals using a fake emulator; it is not a guest acceptance test.
