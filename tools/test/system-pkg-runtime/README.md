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
