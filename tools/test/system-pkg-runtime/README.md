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
