# Installed-media boot observation

Run through `build-bsd boot-observe --boot-observation-policy POLICY.json
--output /usr/obj/usr/src/NEW-DIRECTORY`. `plan` prints the invocation without
starting QEMU or creating output. This is a diagnostic tool, not an operational
qualification suite. It never reports PASS or marks any security/service gate
qualified. Existing bootstrap media can test the runner, but cannot prove an
installed system works.

Format 1 requires exactly these fields:

| Field | Input |
| --- | --- |
| `format` | Integer 1 |
| `qemu` | `{ "path": "/absolute/executable", "sha256": "64 lowercase hex digits" }` |
| `qemu_data` | Absolute QEMU data directory |
| `firmware_code` | Path/hash binding of the read-only firmware code |
| `firmware_variables` | Path/hash binding of explicitly enrolled variables |
| `boot_media` | Path/hash binding of the complete boot disk |
| `data_disks` | Ordered array of path/hash bindings; may be empty |
| `cpus` | Integer 1–256 |
| `memory_mib` | Integer 512–65536 |
| `seconds` | Integer 15–7200 |
| `ssh_forward_port` | Null, or integer 1024–65535 on host loopback |

Use canonical regular file inputs without aliases or QEMU option separators.
The boot disk is the first virtio block device. Data disks follow in array
order; their identity must match the authenticated guest storage policy.
Only private copies of variables/data are writable. Input files and runner
sources are rehashed after the observation. Private data copies are retained
with output hashes for later explicitly selected persistence tests.

Networking uses `restrict=on` with the explicit host loopback forwarding rule.
It does not configure the guest interface or enable sshd. Format 1 only forwards
a port. Format 2 adds the explicit external SSH probe described below.
The runner enables Q35 SMM and supplies firmware images, but observed firmware
and guest enforcement must still be checked by the security qualification suite.
The explicit QEMU data directory must contain physical directories and regular
files, without symlinks or special files. Its relative names, directory entries,
file sizes and SHA-256 hashes are recorded before launch and compared after exit.
Additions, removals, renames, changed bytes or an unreadable final tree make the
observation INPUT_CHANGED. This measures the directory; it does not authenticate
its origin. The builder must keep inputs quiescent. QEMU's host libraries and
other execution dependencies are not a fully measured toolchain.

`result.json` records OBSERVED, OBSERVATION_TIMEOUT, GUEST_FAILURE,
HARNESS_FAILURE, INPUT_CHANGED or SSH_PROBE_FAILED. A timeout exits 124 and is never a clean
shutdown claim. OBSERVED requires exit zero and QMP guest poweroff evidence;
external termination or missing lifecycle evidence is HARNESS_FAILURE. Serial
fatal markers are checked again after exit. A forced timeout remains a timeout
even if termination requires SIGKILL. QMP lifecycle evidence is recorded independently. Input/setup
errors fail before observation and remain in the build-bsd step log; partial
work directories are retained. Serial startup errors beyond the small fatal
marker set require review; absence of a detected error proves no service works.

Run `python3.12 -B tools/test/boot-observe/runner_test.py` from the source root
for native policy/command-boundary tests. The build-bsd ATF case
`boot_observation_plan` covers frontend scope, forwarding and action constraints.

QMP collector startup is inside the QEMU cleanup scope. If it raises after
process creation, the runner terminates and waits for its child, with the
existing kill fallback. The exception remains a failure and no success receipt
is produced. Native mocked-process regressions exercise both cleanup paths;
they do not launch QEMU or qualify guest behavior.

Serial fatal-marker scanning is incremental for the runner's append-only QEMU
log: subsequent polls read newly appended bytes, retaining enough trailing bytes
to detect markers split across writes or chunks. Each pass stops at the file size
observed at entry, so continuous guest output cannot keep the collector inside
one scan indefinitely. Observed truncation or inode replacement restarts scanning;
a fatal marker already seen remains a failure even if the log later disappears
or is replaced. Nonregular files and symlinks are rejected. This is diagnostic
log handling in a private trusted-host workspace, not a hostile-host tamper proof.
Native tests use real temporary log files and mock QEMU lifecycle objects; no
VM starts during runner_test.py. SSH forwarding still does not qualify SSH.

## External SSH command observation (format 2)

Format 2 contains all format-1 fields, sets `format` to 2 and adds `ssh_probe`.
`ssh_forward_port` must be non-null. The probe object has exactly these fields:

| Field | Input |
| --- | --- |
| `client` | Canonical executable path/SHA-256 binding for the SSH client |
| `known_hosts` | Canonical file path/SHA-256 binding containing the independently obtained guest host key |
| `identity` | Canonical private client-key path/SHA-256 binding; no group/other permission bits |
| `user` | Explicit guest account name |
| `command` | Explicit remote shell command, at most 4096 encoded bytes, without NUL |
| `stdout_sha256` | Expected lowercase SHA-256 of the exact command stdout bytes |

These three path/hash bindings use the same `{ "path": ..., "sha256": ... }`
shape as other inputs. SSH paths cannot contain whitespace, quotes, backslashes, dollar signs or percent
tokens: OpenSSH option parsing and path expansion must preserve literal inputs.
Provision the corresponding authorized key and matching guest host key through
the normal installation/configuration workflow. The known-hosts entry must match
`[127.0.0.1]:PORT`. Do not obtain and trust a key from the unverified connection
being tested. Key contents are never copied into the observation directory;
private-key identity hashes and paths are retained in its private input record.

The client uses strict host-key checking, no host-key updates, no user SSH config,
no agent, no multiplexed connection, no forwarding, no PTY and no interactive
password authentication.
The probe selects public-key authentication, disables host-based authentication,
and excludes certificate algorithms. An explicit null certificate source disables
OpenSSH's automatic adjacent-certificate search. This probe does not exercise
certificate-based login. OpenSSH may read the identity's adjacent `.pub` file;
its presence or absence and content hash are recorded and rechecked after the
observation. An added, removed, changed or aliased sidecar invalidates evidence.
These are consistency checks in the trusted, quiescent builder, not protection
against a hostile host changing inputs and restoring them between checks. The remote command is deliberately interpreted by the
guest account's shell; no host shell interprets it. Use a bounded, noninteractive,
idempotent diagnostic command: failed attempts can be retried during startup.
Each attempt has at most five seconds, bounded by the remaining observation time;
after each failure the runner waits at least five seconds before retrying.
Stdout/stderr files and attempt records remain in the observation directory.
A match requires exit zero and the exact expected stdout digest. Attempts stop
following the first match; this does not test continued service availability.

A requested probe that never matches yields SSH_PROBE_FAILED if the guest
otherwise powers off cleanly. Existing input-change, harness, guest-failure and
timeout results take precedence. The guest must still shut down normally for
OBSERVED; the probe does not itself request shutdown. `ssh_probe.matched` records
only the selected command observation. `ssh_qualified` and all whole-system
qualification flags remain false: login variants, su, SFTP, host-key persistence,
account policy and other operational cases require their own integrated evidence.
Native tests mock the subprocess and never connect to a host or start QEMU.

Full observer-flow native tests invoke the runner's main function with real
private input/output files and mocked QEMU, SSH and QMP. They check final exit
status and retained reports for successful/failed probes, changed ROM/public-key
inputs and late serial failure. These tests do not establish guest or SSH behavior.

## Disposable guest startup probe

`startup-probe.sh HOSTNAME ENFORCING [EXPECTED-DAEMON ...]` is a bounded
first startup check for a disposable guest. It requires a root SSH session,
checks the explicitly expected hostname and BIP enforcement value, checks that
random initialization bypass counters are zero, reads fresh random bytes, and
runs the packaged `tty_open_test:private_slave` case. That case exercises PTY
I/O and denial of access after dropping to an unrelated user. Each optional
daemon name is checked for a running process; this is not a functional daemon
test. The script requires a real `passed` ATF result, not a skip.

On success it schedules guest poweroff in one minute and emits exactly
`BIP_STARTUP_PTY_SMOKE_OK` plus a newline. **Run it only in the explicitly
selected disposable VM.** Do not execute it on the builder. To use it with
format 2, put its bytes in the explicit remote `/bin/sh -c` command, passing
hostname, enforcement value and daemon names as shell arguments. Bind the
expected stdout digest and retain the selected script bytes/hash with the
observation inputs. The remote command limit remains 4096 bytes and each
attempt remains limited to five seconds. The script uses a new temporary
directory per attempt and removes only that directory.

The normal packaged SSH server, network configuration and host/client keys
must already be provisioned. This probe does not install or replace guest
software, stop devd/auditd, configure an interface, or change enforcement.
Its checks do not qualify password/PAM login, su, SFTP, console login,
audit event delivery, logging, or service persistence. Those require their
own operations and evidence. A successful probe also does not override the
observer's input checks or requirement for a clean guest poweroff.
