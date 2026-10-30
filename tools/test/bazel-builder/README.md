# Ordinary offline builder installation fixture

This is test tooling for a disposable VM, not an installer or production build
backend. It uses the complete selected package inventory. No selected program
list is embedded in the fixture.

`pkg -r` only relocates installation and supplies PKG_ROOTDIR to hooks; it does
not chroot the hook interpreter. The reviewed pkg2.8.4 src/main.c and
libpkg/scripts.c establish this distinction. This fixture uses actual `pkg -c`
chroot execution. To provide the shell and dynamic interpreter before preinstall
hooks execute, it first extracts **all selected package payloads** using maintained
payload_extract.py. It then performs an ordinary local package installation with
scripts and triggers enabled. There is no register-only operation or invented
construction annotation. Package-file integrity is checked after installation.

## Explicit inputs

- A read-only mounted transport filesystem with format1 transport.json,
  inventory_sha256, layout_sha256, pkg_static_sha256 and the package archive list.
  The current transport-v2 directory adds those files/fields without changing
  the manifest format number. Parent VM runner binds the input disk hash.
- Exact inventory.json and root-layout.json matching the transport hashes.
- Maintained capimage Python helpers (all sibling .py files; hashes recorded).
- A new empty target directory on a separate writable virtio UFS filesystem,
  beneath a root-owned0700 parent. It must not be the fixture root or tmpfs.
- A disjoint empty report directory on retained storage.
- Explicit normal installed Java/Bash paths owned by selected packages.

The VM must provide Python and its runtime, tar, file, mount/umount, devfs,
sysctl, chroot and their dependencies. The kernel must support nullfs/devfs.
The package engine is explicit, hash-bound and required to be static. The input
mount is exposed read-only inside the target. A temporary devfs exposes only
null, zero, random and urandom; backing disks must not be visible there.

Example inside the parent's **2 GB** disk-backed disposable VM, after mounting
its prepared input/output filesystems and creating empty guarded directories:

```
python3.12 /tests/bazel-builder/install.py --disposable-vm \
 --input /inputs --target /builder/private/root --output /builder-report \
 --inventory /inputs/inventory.json --layout /inputs/root-layout.json \
 --backend /tests/capimage --java /usr/local/openjdk21/bin/java \
 --bash /usr/local/bin/bash --timeout 3600
```

All archives are selected from the manifest; their historical host paths are
not used as guest paths. Inventory bytes are checked before archive paths are
rebound. Package registration results must match every selected name/version,
with no extras or omissions. Postchecks execute real Bash and Java, require
account databases, and reject package checksum or reported hook failures.
Timeouts kill the command process group and retain failure evidence. No failure
is converted into a skip. Source inputs are rehashed before success. Temporary
mount cleanup failures turn the result into FAIL. The installed target and logs
remain for inspection.

`test_install.py` checks path overlap/symlink/nonempty guards, transport archive
escapes and duplicate identities, malformed hashes/versions, and mount matching.
These native checks do not qualify guest execution. Full installation, hook
behavior and resource consumption remain pending parent VM review/execution.
A successful fixture proves bounded ordinary package installation and runtime
prerequisites, not Bazel compilation or package publication.

Frontend review: no production backend changes are warranted for this fixture.
Future maintained Bazel package-build integration must consume the validated
builder result and retain the normal make packages/publication contracts.

## Static launcher and disk setup

Build the static launcher through maintained Make:

```
env MAKEOBJDIRPREFIX=/usr/obj make -C /usr/src buildenv \
 'BUILDENV_SHELL=make -C /usr/src/tools/test/bazel-builder -j16 all'
```

The launcher case is `tools/test/bazel-builder/builder_test:ordinary_install`.
ATF configuration can override `python`, `setup`, and `config`; defaults refer
only to fixture files beneath `/tests/bazel-builder`. `setup.py --config FILE`
takes exactly these explicit JSON settings (example devices are parent-created
VM disks, never host disk instructions):

```
{
  "input_device": "/dev/vtbd1",
  "output_device": "/dev/vtbd2",
  "input_mount": "/builder-input",
  "output_mount": "/builder-output",
  "python": "/usr/local/bin/python3.12",
  "installer": "/tests/bazel-builder/install.py",
  "backend": "/tests/capimage",
  "java": "/usr/local/openjdk21/bin/java",
  "bash": "/usr/local/bin/bash",
  "nullfs_module": "/boot/kernel/nullfs.ko",
  "timeout": 3600
}
```

Setup requires explicit unmounted whole virtio devices, rejects the mounted boot
disk and its parent, and requires zero output header bytes before formatting.
This guard supplements the parent's fresh blank disk contract; it is not proof
that every sector is empty. Input/output images and matching kernel/modules must
be selected and hash-bound by the parent runner. No existing system disk is
selected by discovery. Additional utilities: newfs, kldstat and kldload.

The script loads the supplied matching nullfs module when needed. It writes
installation logs and reports to the output disk, never the ATF tmpfs directory.
The retained setup record is written before unmount and explicitly says
cleanup_complete=false; the final serial JSON and ATF exit establish cleanup.
A failed unmount fails the case. Bash's runtime numeric version and Java's
upstream release version are compared with their selected owning packages;
packaging revision suffixes are not runtime version numbers. These are runtime
smoke checks, not full Bash/JDK qualification.

Six native guard tests pass; the static launcher compiles. No VM has been run
by this implementation agent. Real hook errors, immutable file flags interfering
with reinstall, missing devices, or package checksums altered by legitimate
post-install actions remain failures to investigate, not reasons to skip checks.

### Runner timeout integration

The static test declares a 3600-second timeout, within the maintained ATF
metadata parser's supported range. For an explicitly authorized longer run,
pass the runner override:

```
--atf-case-budget tools/test/bazel-builder/builder_test:ordinary_install=7200
```

The runner records the declared timeout and explicit execution budget separately.
The first attempted launch was rejected before VM startup because the earlier
7200-second declaration exceeded the parser limit; this is an integration fix,
not runtime qualification. The install command timeout remains an explicit
settings-file input.

### Implicit package parent directories

Ordinary pkg 2.8.4 creates missing parent directories with root/wheel ownership
and mode 0755. Archives need not contain entries for every ancestor. The fixture
`layout.py` derives this closure from the complete inventory, using the explicit
`pkg-parent-policy.json` contract. It preserves existing layout and package
metadata, rejects non-directory ancestors and replacement layouts, and requires
the selected pkg version to match the policy. It does not assign package
ownership to generated directories or change the shared strict extractor.

```
python3.12 -B tools/test/bazel-builder/layout.py \
    --inventory /path/to/inventory.json \
    --initial /path/to/root-layout.json \
    --policy tools/test/bazel-builder/pkg-parent-policy.json \
    --output /path/to/new-layout.json --receipt /path/to/new-layout-receipt.json
python3.12 -B tools/test/bazel-builder/test_layout.py
```

Outputs must be new, distinct files. The planning receipt binds inventory,
initial layout, policy, producer and backend source hashes, plus the resulting
layout hash. The transport must carry that resulting layout and its updated
hash; changing a local file alone does not update a previously built input disk.
This is fixture compatibility planning, not installation or production image
qualification. Maintained generated-layout consumers can use the existing
schema without a new build frontend option.

The full 335-package builder inventory required 2,746 implicit parents. Planning
with the strict extractor and package-derived account resolution passed for
66,576 objects. Extraction and ordinary pkg installation still require VM
qualification; these planning checks cannot establish their success.


## Resource-bounded commands in initialized builders

`resources.py` is a qualification wrapper, not a production build interface.
It runs an explicit executable inside a disposable VM, retaining stdout/stderr,
JSONL samples and a final result in a new output directory. The initialized
builder fixture supplies its command; the blank-disk installation guard remains
unchanged. Example invocation shape:

```
python3.12 /tests/bazel-builder/resources.py --disposable-vm \
 --budget /inputs/build-budget.json --output /workspace/build-report \
 --filesystem /builder-output --filesystem /workspace \
 --device vtbd2 --device vtbd3 -- /usr/sbin/chroot /builder-output/private/root \
 /usr/bin/make -C /usr/ports/devel/bazel9 package
```

The budget JSON must explicitly specify all six fields: max_physical_memory_bytes
(at most 25769803776 bytes, or 24 GiB), max_elapsed_seconds(1..86400), min_free_memory_bytes,
min_free_disk_bytes, max_used_disk_growth_bytes, and sample_interval_seconds
(0.1..30). Byte limits are nonnegative integers. Duplicate, nonfinite, missing or
unknown fields are rejected. Choose these limits before execution; retain failed
runs if a reviewed budget subsequently changes. A 24 GiB builder declares
max_physical_memory_bytes=25769803776; the higher parser ceiling does not raise
any existing run's configured budget.

Preflight and sampled violations fail the run. Measurement failures are fatal.
On termination, the wrapper kills the command process group and preserves the
report. It records raw FreeBSD memory counters, filesystem available/used bytes,
cumulative iostat device statistics, command CPU time, maximum child RSS and
block-operation counts. No host-installed library or provider is inferred.

These measurements have explicit limits: sampling can miss peaks; free pages
exclude reclaimable inactive pages; child maximum RSS is not the aggregate peak
of all concurrent processes; cumulative iostat output is not a latency histogram.
A passing budget run is not a disk-performance regression comparison. Host QEMU
memory and paired baseline/modified IO benchmarks remain separate requirements.
The native test_resources.py suite checks budget semantics, evidence preservation,
missing metrics, failed commands and process-group termination. VM execution of
this wrapper remains a separate qualification gate. No production build-bsd
option changes are required for this test wrapper.

### Build inside an initialized builder

`build.py --config build-settings.json` is a separate fixture. It mounts an
explicit initialized builder image without formatting it and verifies the
successful installation receipt before using its root. The original `setup.py`
continues to require and format a blank installation target.

Three distinct whole virtio devices are required: read-only source transport,
initialized root clone, and new blank UFS workspace. The input and root
mountpoints must already exist as safe empty root-owned directories on the
bootstrap filesystem. The workspace is mounted at the builder's `/usr/obj`;
source inputs are exposed read-only at `/inputs`. Work, packages and resource
logs stay on disk. Restricted devfs supplies random/zero/null devices without
exposing the fixture disks.

The settings file requires exactly these fields (paths are explicit fixture
inputs, not discovered host paths):

```
input_device, root_device, workspace_device, input_mount, root_mount,
root_relative, installation_receipt, installation_receipt_sha256,
sources_manifest, sources_manifest_sha256, nullfs_module,
python, resources, budget, javac_options, bootstrap_args, package_tool
```

`root_relative` and `installation_receipt` are relative to the mounted root
disk. `sources_manifest` is relative to the read-only input filesystem. That
manifest uses format 1 with `ports_archive` (file/sha256), `ports_directory`,
`distfiles` (array of file/sha256 records), `origin`, and `package`. All source
paths are canonical relative paths. The complete source archive is checked
before extraction: duplicate members, special devices, non-directory ancestors,
escaping links and unresolved/cyclic hardlinks fail. Symlink targets traversing
another archive link are conservatively unsupported.

The fixture invokes maintained ports `make package`, with normal patch/build/
stage/package hooks and dependency checks. `USE_PACKAGE_DEPENDS_ONLY=yes` makes
missing dependencies fail instead of silently rebuilding them. It passes all
guest logical CPUs as `MAKE_JOBS_NUMBER`, verifies the selected port and produced
archive identities, and retains the package SHA256. It does not install the new
package. The supplied `resources.py` budget bounds the build command; preparation
and teardown are outside that command's performance measurements.

Run the static `builder_test:ordinary_port_build` case, with an explicit runner
case budget when longer than the declared 3600-second default is needed.
`build.py` must be staged with `setup.py` and `resources.py`. The runner must
clone the initialized disk at its original capacity and attach a separate new
workspace disk; increasing the original disk or using a RAM filesystem is not
an alternative. A full committed ports snapshot and pinned distfiles are source
inputs, not a hand-selected mini world.

The workspace `build-result.json` is written before unmounting and explicitly
has `cleanup_complete=false`. The final serial JSON and ATF exit status establish
cleanup success; the disk record alone cannot establish it. A passing build
records `runtime_qualified=false`: executing and qualifying the resulting Bazel
binary remains a separate required step. RAM and disk sizing are explicit trial
budgets until measured; an OOM or missing offline source remains a failed run.
