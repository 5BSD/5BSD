# Managed local action cache and installation materialization (2026-11-04)

## Cache boundary

Canonical install archives encode inode relationships, ownership, modes and
explicit timestamps. They are normal cacheable file outputs. Physical installation
trees are a different contract: Bazel directory artifacts do not serialize all
POSIX/BSD installation metadata. `bsd_stage` now requests no-cache/no-remote for
its materialization spawn, so disk/remote content caches never upload or restore
that tree. This does not change the directory-artifact format or repair an old
cached tree. Existing local outputs may remain up to date; their link graph must
still be verified before packaging. The legacy verifier already checks that graph.
Full-system consumers should use canonical archives and bulk materialization.

The rule now passes executable FilesToRun providers, preserving native installer
runfiles, and accepts explicit runtime files for file-based tools. The native
bootstrap installer opts into build runtime paths for its declared native libmd.
Its production installation binary and probe policy are unchanged. BOOTSTRAP_XINSTALL
retains Make's original bootstrap behavior; this is not a general probe exclusion.

## Maintained frontend configuration

Format-5 source inputs optionally declare:

```json
"action-cache": {
  "name": "install-qualification",
  "max-bytes": 8589934592,
  "max-age-seconds": 86400,
  "idle-delay-seconds": 5,
  "min-free-bytes": 10737418240
}
```

Absence/null keeps the previous disabled-CAS behavior. This is an action cache,
separate from the module-download `repository-cache`. The backend derives a path
under the checkout's standard `/usr/obj` state, in `action-caches/<name>`. Cache
parents must be private, builder-owned directories; symlinks and shared modes are
rejected. All limits are explicit typed inputs, not arbitrary Bazel flags. The
age fits positive 32-bit seconds, byte limits fit positive signed 64-bit values,
and idle collection delay must be shorter than the server idle timeout.

Bazel 9.3.1's native disk cache and idle GC options are used. GC size/age are soft
idle collection targets, not a hard peak quota. The configured free-space reserve
is checked before Bazel work; it does not monitor every write during a long build.
The cache remains opt-in pending broader system qualification. Signing secrets
must not be action inputs; this interface introduces no remote cache service.

Optional `build-state` is a simple identifier selecting a private named output
state while retaining the checkout's SDK/module staging and action cache. Omitting
it preserves the existing output root. Named states make genuine empty-output-base
qualification possible through build-bsd itself, without hand-replacing build
commands. The existing global frontend lock still serializes its build invocations.
The receipt records the actual output root and resolved cache policy. Existing
build-bsd.c JSON dispatch was reviewed; backend/tests/manual change together and
no new C CLI switch is required.

## Results

The maintained profile executes twenty-seven frontend contract methods and the
native installation validator in two Bazel wrappers. Cache/state tests cover
invalid/injected policies, limits, private ownership/modes, symlinks, reserve
failure and isolated output roots. The native fixture checks an out-of-order
three-link chain, symlink, payload and logical metadata. Its validator is tagged
external because inode identity is runtime filesystem state; its actual body runs
in every phase rather than reusing a PASSED result by file digest.

`install-cache-roundtrip.py` uses build-bsd for cold-output, restored-output and
unchanged phases. Both first output bases are newly created; their CAS is already
primed by preceding qualification runs. This is not a cold/empty-CAS timing test.
In each fresh output base all 66 compiler actions and the archive are disk hits.
The physical staging action executes successfully and is not a cache hit. The
actual test body executes each time. XML-report synthesis is recorded separately;
it may be cached without substituting for test execution.

All archive bytes match the initial immutable capture. Inspection checks encoded
uid/gid zero, explicit epoch 42, root mode 0750, payload mode 0440, all hardlink
roots and the symlink target. Independent BSD tar extraction below the evidence
root verifies actual inode identity, symlink, bytes and modes with no host install
and no privileged ownership application. In the unchanged phase compiled/archive
outputs and the existing physical tree stay up to date; the inode validator still
executes and passes. This bounds repeated materialization cost to needed output
creation rather than disabling compilation caching.

The maintained older hardlink helper retains all six original cases: actual chain,
cycle, self-cycle, missing target, symlink target and inode-mode mismatch. Its fresh
output-base check now requires actual uncached staging, not a misleading tree cache
hit. Its copied workspace uses the matching maintained probe pins/lock and explicit
Skylib version. Module inputs are staged and the input cache remains unchanged.
This separate helper uses explicitly hashed host install/shell support and is not
a hermetic native-toolchain result; the new fixture uses the source-built bootstrap
installer. Canonical archive disk hits are established by the new round trip.

## Retained failures

- Initial fixture analysis rejected a variable **kwargs expansion in BUILD syntax;
  explicit rule attributes correct it, with no product behavior change.
- The first native test inspected a runfiles indirection instead of the actual
  staged symlink. The corrected adapter follows a regular payload to its real
  output parent, then checks the actual symlink and all inode relationships.
- The older helper lacked matching module dependencies/lock context. Both setup
  failures remain; it now uses the maintained probe workspace generator and lock.
- The first round-trip helper counted both test execution and XML synthesis as
  one TestRunner spawn. Its cold build passed, but the harness failed. The corrected
  classifier requires actual test-setup execution and records XML synthesis apart.
  A new round trip uses different, genuinely empty named output roots.

Evidence under `/usr/obj/usr/src/`:

- `bazel-managed-cache-initial-r{1,2,3,4}-20261104` (r4 final)
- `bazel-physical-stage-cache-contract-r{1,2,3}-20261104` (r3 final)
- `bazel-managed-install-cache-roundtrip-r1-20261104` (classifier failure retained)
- `bazel-managed-install-cache-roundtrip-r2-20261104` (three passing phases)
- `bazel-managed-action-cache-final-review-r1-20261104`

The failed native adapter run retains BEP and stderr summaries, but its detailed
test log was referenced in a mutable Bazel output tree and was overwritten by a
later run. That original detailed report is not claimed as retained evidence.
Capture failed test reports before returning from the frontend in a follow-up.

## Remaining gates

This closes the isolated managed local-CAS/physical-stage boundary demonstrated
above. It does not qualify all kernel-generated/fixture trees, full world/boot
aggregation, every option and dependency mutation, workspace relocation, remote
cache, filesystem sandboxing, runtime/VM behavior, pkgbase/publication or fair
CPU/memory/disk performance. Native compilation caches stay subject to full-system
and bootstrap qualification before production/default changes. Physical-output
corruption is a verification failure, not a silently repaired policy exception.
Make remains production/default; BIP remains excluded. No host upgrade, reboot,
installation or publication occurred.
