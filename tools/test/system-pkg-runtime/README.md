# Complete pkgbase normal runtime qualification

This driver boots the complete native pkgbase image through its ordinary loader,
Capsule/init and rc path. It does not replace init or rc with a probe. Read
`tools/build/bazel/SYSTEM-IMAGE-BOOT-QUALIFICATION.md` for the exact evidence and
remaining gates; construction success does not establish a runtime pass.

First build `//:amd64_system_boot_test_image` through the maintained format-5
`build-bsd bazel-test` interface. Select its `.img` and `.report.json` from the
resulting immutable qualification capture. Then supply an explicit JSON plan:

```json
{
  "format": 1,
  "qualification": "/usr/obj/usr/src/your-image-qualification",
  "target": "//:amd64_system_boot_test_image",
  "image_output": "amd64_system_boot_test_image.img",
  "report_output": "amd64_system_boot_test_image.report.json",
  "qemu": "/usr/local/bin/qemu-system-x86_64",
  "qemu_img": "/usr/local/bin/qemu-img",
  "bios": "/usr/local/share/qemu/bios-256k.bin",
  "ssh": "/usr/bin/ssh",
  "qemu_data": "/usr/local/share/qemu",
  "cpus": 4,
  "memory_mib": 2048,
  "terminal_rows": 24,
  "terminal_columns": 80,
  "deadline_seconds": 900,
  "max_rss_mib": 4096,
  "max_overlay_mib": 8192,
  "console_user": "root",
  "password": "BazelVMQual1!",
  "ssh_user": "bazeltest",
  "user_uid": 2001
}
```

These credentials match the private test site's actual guest `pw` provisioning.
Never use this site or password as production defaults. Tool/firmware paths,
resources and inputs are explicit; no alternate image or authentication fallback
is attempted. SSH host identity is read through the authenticated guest serial
session and pinned in a private known_hosts file. The host SSH client has no
user-config, agent, public-key or interactive-authentication fallback.

Run with a fresh output directory under the standard object root:

```sh
/usr/local/bin/python3.12 -B /usr/src/tools/test/system-pkg-runtime/run.py \
  --plan /usr/obj/usr/src/your-vm-plan.json \
  --output /usr/obj/usr/src/your-fresh-normal-boot-result
```

QEMU uses TCG, an on-disk qcow2 overlay, 127.0.0.1-only SSH forwarding and the
explicit RAM/CPU limits. The driver owns and stops only its own QEMU process.
No host install, ZFS import, mount, module load or reboot is performed. It keeps
serial/authentication logs, source/tool/image bindings, the plan, sampled QEMU
CPU/RSS, maximum observed allocated overlay bytes and result status. It checks
normal shutdown and unchanged backing bytes on success. Sampling does not bound
between-sample peaks or host page-cache memory, and is not comparative performance
or disk-throughput qualification. Kernel panic/lock diagnostics fail immediately.

A failed run retains its own overlay and evidence. Reusing that mutated overlay
as a fresh normal-boot proof is not supported. The guest test is not Secure Boot,
Veriexec enforcement, real version upgrade/rollback, or all service qualification.

The serial harness answers standard absolute-cursor/DSR size probes using the
explicit terminal dimensions, with position clamping. It does not invent answers
for unknown-cursor queries or claim to emulate a full display. It waits for the
actual login shell prompt before sending commands, so login-profile terminal
readers cannot consume test input. The actual guest stty/resizewin result must
match the declared dimensions. Kernel and startup-shell failure diagnostics fail
qualification immediately. Run `//tools/test/system-pkg-runtime:serial_terminal_test`
through the normal frontend inputs to test fragmented protocol handling.

## Complete installed baseline audit

Use plan `format: 2` and add `metalog_output` naming the captured image target's
`.METALOG` output, plus a positive `audit_deadline_seconds` within the whole-VM
deadline. The runner authenticates the construction report and METALOG,
requires exact coverage of all declared files and directories, and binds every
regular file to its captured construction SHA-256. It streams the resulting
`installed.mtree` over pinned-host SSH to the actual guest's read-only
`/usr/sbin/mtree -e -f /dev/stdin -p /`. No repair/update flags are used.

Declared directories with no baseline children receive mtree `ignore`: their own
metadata is checked, while undeclared runtime children are not traversed. All
baseline parents must themselves be declared directories. This is derived from
the complete inventory, not a device-path exemption list. Acceptance requires
exit zero **and an empty diagnostic log**: mtree can report missing paths or
traversal errors without a failing exit status.

The audit compares object type, numeric UID/GID, permissions, flags, symlink
text and regular-file content. `-e` permits extra runtime objects; it does not
omit declared objects. This baseline check does not verify timestamps, hardlink
inode identity or inventory newly created runtime files. Those limits are
recorded in the result. Normal firstboot may change packaged accounts, databases
and fixture state: every difference is retained in `installed-audit.log`, causes
failure, and requires review against its actual producer. No configuration tag,
mutable directory or service name silently exempts baseline records.

The host retains the complete specification and log hashes, object counts and
actual mtree exit status. A failed audit is not a normal-shutdown pass: the
runner stops its owned VM and retains the overlay. Format 1 preserves the earlier
startup/authentication scope without claiming this additional installed audit.
Run `//tools/test/system-pkg-runtime:installed_audit_test` through the maintained
frontend to verify complete coverage and rejection of changed, missing, duplicate
or unsupported specification records. No new C frontend option is needed: the
existing format-5 target/test inputs carry this test and the image artifacts.

## Prove firstboot transitions

Format 3 adds `firstboot_policy` (an explicit JSON file) and
`firstboot_deadline_seconds`. It retains the complete original mtree spec and raw
log. The policy has exact format-1 fields:

* `baseline_master`, `baseline_group`: source files whose hashes must equal the
  captured image's `/etc/master.passwd` and `/etc/group` payloads.
* `producer`: the source whose hash must equal the actual `/etc/rc.local` payload.
* `changes`: account name to declared field changes. Existing accounts preserve
  every undeclared field. New accounts require every field except name/password:
  `uid`, `gid`, `class`, `change`, `expire`, `gecos`, `home`, `shell`, as strings.
* `group_additions`: existing group name to an exact ordered list of added users.
* `consumed_files`: distinct canonical paths of declared empty firstboot markers.
* `zfs_archive_tracking`: explicit boolean permitting only the `uarch` bookkeeping
  bit to vary. Security flags, modes and ownership remain exact.
* `db_compare`: `qualification`, `target`, `output` selecting the actual captured
  `//tools/test/system-pkg-runtime:db_compare` executable built through the normal
  frontend. No mutable executable lookup or host replacement is used.

The account set must match the console/SSH accounts whose positive **and negative**
authentication checks have already passed. A fresh guest tar snapshot includes
master.passwd, group, public passwd and both database files. Account/group content
and order are checked against the complete baseline and declared changes; no
other account or membership may change. Password salts are not predicted: only
the exercised accounts may carry new encoded passwords. The actual live databases
must then equal all logical records from real guest `pwd_mkdb` regeneration of
the checked master, in a new private directory. The public passwd projection is
also exact. The comparator opens both databases read-only and checks both key sets
and values; it does not compare physical database page layout.

The temporary helper and rebuild directory are removed after success. Live account
files are never rewritten. Each consumed marker is separately checked absent.
The audit then accepts only content hashes bound to these proofs, those specific
marker removals, and the explicitly selected archive bit. It rejects every other
raw diagnostic, missing object or security metadata change. The raw mtree status
(normally 2 for real firstboot changes), complete diagnostics, classified changes,
input hashes, commands, snapshot and proof are retained. Format 2 remains the
strict unchanged-baseline check. These are fixture qualification inputs, not an
operating-system mutability policy or BIP.

Relevant native test targets are `db_compare_test`, `firstboot_accounts_test` and
`mtree_reconcile_test` in this package. The DB test uses actual declared native
pwd_mkdb and shell inputs, tests equal/changed/extra logical records and verifies
that comparison does not modify either database. The Python tests reject account,
membership, password-proof and raw-diagnostic drift. Existing frontend format-5
`targets`/`tests` carry these targets; no C frontend option or backend switch is
needed.

## Real boot-environment upgrade qualification

`prepare_repository.py --plan PLAN --output DIRECTORY` prepares a **private test
repository**, never a combined publication or a `latest` update. Its format-1 plan
selects the complete captured package index/families, exact package output prefix,
explicit native pkg tool, target ABI/OSVERSION, signing private key, matching public
key and a different public key. Every indexed package is copied and hash checked;
normal `pkg repo` signs the catalogue. The maintained hardware verifier imports
that catalogue with its public key and fetches every archive; the different key
must fail actual verification. Only public keys ever enter a VM or HTTP server.
The reserved pkg `files.pkg` catalogue is metadata, not an installable archive;
other malformed archives remain errors.

Format 4 retains all format-3 baseline/authentication/firstboot checks and adds
`upgrade_policy`, an explicit format-1 JSON file with these fields:

* `repository`: the passed preparation output directory.
* `baseline_version`, `baseline_kernel_revision`, `kernel_revision`,
  `kernel_sha256`: expected old/new package and actual kernel identities.
* `candidate`: a new, unused BE name.
* `pkg_path`: an executable declared in the captured image (the private fixture
  supplies its SDK pkg tool). No host executable fallback is performed.
* `guest_host_address`: the QEMU user-network address reaching the host's
  loopback HTTP server (normally `10.0.2.2`). The server binds only 127.0.0.1.
* `persistent_dataset`, `persistent_path`: an explicitly shared image dataset
  outside the BE parent, and a previously absent test file beneath its mountpoint.
* `deadline_seconds`, `reclaim_deadline_seconds`: positive bounded phase budgets.

Upgrade policy format 2 adds `baseline_packages`, with exact `qualification`,
`target` and `output` fields selecting the old captured package-family JSON.
The captured version and distinct package count must match the explicit baseline
version and image report. The actual guest database must then match those names
and versions exactly. Candidate checks use the new signed repository inventory;
rollback checks use the old inventory. Format 1 retains identical-name-set
qualification only. Do not infer the old set from the next repository.

For format 2, normal `pkg upgrade` is followed by `pkg install` for newly declared
base packages and `pkg delete` for obsolete names, inside the inactive BE only.
The final exact inventory and checksum checks reject incomplete transitions,
unexpected dependency removals and leftover old packages. This is a complete-base
VM qualification path, not a production upgrade manager or a general policy for
removing third-party software. Real VM acceptance of these transitions remains
required.

The driver verifies every repository byte/trust key before starting. In the guest
it verifies the signed network catalogue and rejects the wrong key using separate
private databases; active pkg state must remain unchanged. It creates a real BE
clone, mounts it, uses actual chroot pkg with normal scripts/triggers and a
transient devfs, then checks the complete installed version set, non-config pkg
checksums and actual kernel bytes. It cleans temporary inputs, verifies the active
DB is untouched, activates the candidate and reboots the same owned QEMU process.
The default fixture loader follows ZFS bootfs; it must not pin a dataset in
loader.conf. No init/rc replacement, memory-disk root or manual root switching is
used.

New boot and rollback each require the expected dataset GUID, kernel stamp and
bytes, complete package version set, Capsule PID 1, retained signal protection,
running PAM-enabled sshd, pinned SSH host identity, and real positive/negative
SSH and su authentication. A write made to shared data on the new version must
survive rollback. Then the unused candidate is removed, active removal must be
refused, retained/shared GUIDs must survive and pool space must be reclaimed
within the explicit deadline. This is a file/dataset persistence test, not a
claim that application database schemas or data formats can safely be rolled back.

The test runs entirely inside a disposable VM; it does not invoke host ZFS,
install a host upgrade or change the system repository. Full upgraded-tree
metadata, non-default/cross profiles, hardware publication and comparative
performance remain separate gates. The normal format-5 frontend target/test
inputs carry `upgrade_policy_test`; the C build backend remains Make/default.

### Service-failure acceptance guard

The normal runner rejects logged capability-service startup/on-demand failures and
runtime-container cleanup/creation errors, as well as panic/WITNESS/shell errors.
`startup_diagnostics_test` covers real snippets from upgrade R1, whose original
runner passed authentication but omitted service failures. Replaying the full R1
serial log now rejects it; the accepted baseline R8 log remains accepted. This
guard is additional failure detection, not proof of complete service health.
The diagnostic module is hash-bound with the other runner sources.

## Manifest-derived boot-service readiness (format 5)

A format-5 VM plan contains every format-4 field plus `service_policy`, an absolute
path to this exact format-1 policy shape:

```json
{
  "format": 1,
  "qualification": "/usr/obj/usr/src/EXPLICIT-PASSED-NATIVE-CAPTURE",
  "target": "//tools/test/system-pkg-runtime:service_inventory",
  "output": "service_inventory",
  "roots": ["/Capabilities/System"],
  "control_program": "/Capabilities/System/SwitchBoardControl.cap/Units/switchboardctl.unit/bin/switchboardctl",
  "deadline_seconds": 120
}
```

The qualification path must name a real passed native capture; the example is
schema documentation, not a usable receipt or fallback. Select actual configured
bundle roots and a regular control executable present in the captured image.
The usual `/usr/sbin/switchboardctl` alias is a symlink; the policy names its
packaged executable. The helper is uploaded from its hash-verified capture into
a private guest directory. Neither the frozen capture nor the image is modified.

`service_inventory` uses the production libcapbundle parser to enumerate installed
bundles and their service labels, executables, boot activation and endpoints.
There is no hand-maintained required-daemon list. Every boot-activated service
must appear running, with a PID and no pending cleanup, in the real control
service's response. Missing or malformed bundles, duplicate declarations,
truncated status, missing PIDs and missing/unready boot units fail acceptance.
A new boot service therefore becomes required without a runner source edit.

The check runs on the baseline, upgraded boot and rollback, within explicit
service/upgrade/whole-VM deadlines. Complete non-config pkg checksum checks now
also run after new boot and rollback. All raw root-command outputs and a separate
service inventory/state report are retained. Full closeout runtime evidence must
include this readiness coverage; old format-4 mechanism results do not establish it.

This is boot-unit readiness and a real manager status RPC. It does **not** prove
individual provider protocol operations, on-demand/timer/path activation or
arbitrary configurations outside the selected installed roots. Those functional
contracts remain required work for the closeout goal. Host parser/validator tests
are separate from native Bazel and VM acceptance. Use the normal format-5 frontend
target/test inputs for `service_inventory_test` and `service_health_test`.

## Native provider-operation client

`//tools/test/system-pkg-runtime:service_operations` is a PIE consumer binary
built through the maintained format-5 frontend target selection. It is not a
host test and must not contact arbitrary installed host providers. Capture its
native output, then execute it in the owned normal package-runtime VM through
the ordinary authenticated login/service lookup context. It has no alternate
provider transport, fallback, privilege grant or policy bypass.

Select one operation per invocation:

* `time`: real timecmp request, with the returned timestamp bounded by guest
  realtime observations before/after the request.
* `sysctl`: real sysctlcmp read of kern.ostype, compared byte-for-byte and by
  length with the guest kernel's value.
* `notify`: subscribe to a fresh private user.* topic, publish a payload,
  receive and validate the exact framed topic/payload, then unsubscribe.
* `log`: create a logger with a fresh private category, emit a public event,
  flush, then query the same label through exact subsystem/category filters.
  Require the exact event/message, validated lengths and trusted receive clocks.
  Persistent-query visibility is polled for at most ten seconds; transport or
  permission errors fail immediately. This calls the explicit Log API, with no
  syslog fallback. It is implemented and syntax-checked; native/VM acceptance
  remains pending.
* `memory`: observe BSDMemory's reserved memory-pressure state through BSDNotify.
  Wait at most ten seconds for an actual normal/warning/critical sample; missing
  or unknown is never normal. Require attempts to set/clear that reserved state
  to fail with an authorization error, then confirm the read session still works.
  This belongs in the ordinary authenticated user session, not a privileged
  consumer granted the Memory producer's identity.

* `power`: query supported ACPI states through the real provider. Zero supported
  sleep states is valid on virtual hardware; no transition is requested.
* `device`: in an authorized SYSTEM lookup context, enumerate and validate one
  owner-scoped device page. An empty list is valid default-deny policy. This does
  not open devices or qualify all pages. The shipped Device manifest is
  SYSTEM-only: a normal login session must not be made eligible for this probe.
* `device-denied`: in the ordinary login session, first complete a permitted
  Time operation, require Device lookup/enumeration to be hidden or denied, then
  repeat the permitted Time operation. An absent lookup transport or arbitrary RPC failure is not accepted as a
  policy denial. This is visibility qualification, not a successful Device RPC.

The client has a 20-second process deadline and notification receive has a
five-second deadline. Any open, RPC, content or cleanup failure exits nonzero.
It reports one exact JSON success record only after completing the operation.
The libraries perform their normal protocol negotiation and authorization.
Shared dependencies are declared through native cc_binary.dynamic_deps.

Native compilation and PIE/shared linking pass in
`bazel-current-closure-native-r1-20261111`; strict host syntax checks also pass.
The existing six ordinary modes have passed all four phases in
`/usr/obj/usr/src/bazel-current-upgrade-vm-r3-20261114`: baseline, active system
before activation, new boot and rollback. Positive SYSTEM Device access and the
new Log mode have not been qualified. The eight implemented modes do not cover
all providers. BSDMemory is a memory-pressure sampler/publisher, not a
memory-allocation factory; its manifest
intentionally has no IPC endpoint. The earlier factory wording was incorrect.
The memory probe exercises the actual Sysctl-to-Memory-to-Notify path, but does
not inject pressure, stop/restart providers or prove periodic publication over
an extended interval. Manifest-derived readiness remains separate from useful
operation coverage; gate 1 stays open until the required real VM checks pass.

## Ordinary-login operations (service policy format 2)

VM plan format 5 also accepts a service policy with format 2. It retains every
format-1 field and adds `operations`, with exact fields `qualification`, `target`,
`output`, `guest_directory` and `cases`. The first three select the captured
native service_operations binary. `guest_directory` is an explicit canonical
absolute guest staging parent (the current fixture selects /tmp).

`cases` is a distinct nonempty list drawn from time, sysctl, notify, log, memory,
power and device-denied. Positive Device enumeration is deliberately rejected here:
it requires a legitimate SYSTEM context, not an ordinary login or changed
visibility policy. The selected helper is hash-bound alongside the inventory
helper. Root creates a fresh owned staging directory and read/execute-only
program; each operation runs through pinned authenticated SSH as the declared
ordinary user, with an actual UID check before exec. Operation failures or
mismatched/incomplete success JSON fail the service check. The existing service
phase deadline also bounds SSH launch/execution. Successful staging cleanup is
required; failures preserve diagnostic evidence.

The runner repeats these selected operations at baseline, after inactive install
while the old system is still active, after new boot and after rollback. The
post-install active-system check also repeats kernel, package checksum and
authentication checks before activation. This tests that offline pkg scripts do
not leave the running system broken.

Readiness still derives every required boot unit from installed manifests. A
passed ordinary-operation subset explicitly records
`all_provider_operations_qualified=false`; it does not qualify the other
providers, authorized Device access, every provider method or fault recovery.
The goal remains open until all required operation contexts are qualified.
Earlier native service_health/inventory/upgrade-policy targets and the six-case
format-2 VM scenario pass. The Log extension has 11 direct policy tests and a
strict C syntax check; its updated native binary and all four VM phases are still
pending while a concurrent world build refreshes shared SDK inputs. Source-input
verification remains required.

Restricted provider coverage must use its normal authorization paths: existing
approved operator binaries where they exercise the required operation, or
builder-authorized signed test units when a SYSTEM service context is needed.
In particular, Trace requires its declared software attribute; UID 0 alone is not
substitute authority. Do not widen provider visibility or disable enforcement to
make an ordinary helper reach SYSTEM services. Filesystem container operations
also need a legitimate bundle identity, even though discovery is user-visible.
Required boot-unit readiness stays manifest-derived, and operation coverage must
continue to report incomplete until every required context has real evidence.
