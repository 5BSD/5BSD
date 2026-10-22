#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Boot a built 5BSD tree under QEMU and exercise live DTrace devices.

This is a rootless kernel/DTrace smoke test. QEMU does not provide the bhyve
VirtIO DTrace device, so it does not qualify a HyperTrace host/guest session.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess


SOURCE = Path(__file__).resolve().parents[3]


def run_logged(command, log, **kwargs):
    with log.open("wb") as output:
        subprocess.run(command, cwd=SOURCE, stdout=output,
                       stderr=subprocess.STDOUT, check=True, **kwargs)


def stage_config(stage, arch):
    config = {
        "etc/fstab": "/dev/vtbd0p2\t/\tufs\trw\t1\t1\n"
                     "tmpfs\t/tmp\ttmpfs\trw,mode=1777\t0\t0\n",
        "etc/rc.conf": 'hostname="hypertrace-smoke"\n'
                       'sendmail_enable="NONE"\nsshd_enable="NO"\n'
                       'dumpdev="NO"\ndevmatch_enable="NO"\n',
        "boot/loader.conf": ('console="comconsole"\n' if arch == "amd64" else "") +
                            'autoboot_delay="1"\ndtraceall_load="YES"\n'
                            'dttransport_load="YES"\n',
        "etc/rc.local": r'''(
    sleep 2
    echo HYPERTRACE_VM_START
    uname -a
    kldstat
    test -c /dev/dtrace/dtrace && echo HYPERTRACE_DTRACE_NODE_OK
    test -c /dev/dttransport && echo HYPERTRACE_TRANSPORT_NODE_OK
    /usr/bin/timeout 10 /usr/sbin/dtrace -q -n 'BEGIN { printf("HYPERTRACE_DTRACE_BEGIN_OK\n"); exit(0); }'
    echo "HYPERTRACE_DTRACE_EXIT=$?"
    /usr/bin/timeout 10 /usr/sbin/dtrace -q -n 'syscall::openat:entry { printf("HYPERTRACE_SYSCALL_PROBE_OK\n"); exit(0); }' -c '/bin/ls /etc'
    echo "HYPERTRACE_SYSCALL_EXIT=$?"
    /usr/bin/timeout 10 /usr/sbin/dtrace -q -n 'syscall::openat:entry { printf("HYPERTRACE_IMMSTACK_PROBE_OK\n"); immstack(); exit(0); }' -c '/bin/ls /etc'
    echo "HYPERTRACE_IMMSTACK_EXIT=$?"
    vmstat -z | grep -i mbuf
    echo HYPERTRACE_VM_DONE
    /sbin/shutdown -p now
) >/dev/ttyu0 2>&1 &
''',
    }
    for name, value in config.items():
        path = stage / name
        path.write_text(value)
        path.chmod(0o755 if name == "etc/rc.local" else 0o644)
    ttys = stage / "etc/ttys"
    text = ttys.read_text()
    changed, count = re.subn(r'^(ttyu0\s+"[^"]+"\s+\S+)\s+onifconsole',
                             r'\1 off', text, flags=re.MULTILINE)
    if count != 1:
        raise RuntimeError("could not reserve ttyu0 for the smoke output")
    ttys.write_text(changed)
    return config


def normalize_metalog(stage, output, config):
    records = {}
    for line in (stage / "METALOG").read_text().splitlines():
        if line and not line.startswith("#"):
            records[line.split(" ", 1)[0]] = line
    for name in config:
        mode = "0755" if name == "etc/rc.local" else "0644"
        records[f"./{name}"] = (f"./{name} type=file uname=root "
                                 f"gname=wheel mode={mode}")
    for base, directories, _ in os.walk(stage):
        for name in directories:
            path = Path(base) / name
            if path.is_symlink():
                continue
            key = "./" + path.relative_to(stage).as_posix()
            if key not in records:
                mode = stat.S_IMODE(path.stat().st_mode)
                records[key] = (f"{key} type=dir uname=root "
                                f"gname=wheel mode={mode:04o}")
    for key, line in records.items():
        path = stage / key.removeprefix("./")
        if "type=file" in line and "size=" in line and path.is_file():
            records[key] = re.sub(r"\bsize=\d+", f"size={path.stat().st_size}",
                                  line)
    output.write_text("#mtree 2.0\n" +
                      "\n".join(records[key] for key in sorted(records)) +
                      "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new directory under /usr/obj")
    parser.add_argument("--arch", choices=("amd64", "arm64", "riscv64"),
                        default="amd64")
    parser.add_argument("--world-obj", type=Path,
                        help="buildworld MAKEOBJDIRPREFIX")
    parser.add_argument("--kernel-obj", type=Path,
                        default=Path("/usr/obj/5BSD-hypertrace-validation/kernel"))
    parser.add_argument("--qemu", type=Path,
                        help="QEMU system emulator")
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to("/usr/obj") or output.exists():
        parser.error("output must be a new directory under /usr/obj")
    obj_name = {"amd64": "world", "arm64": "arm64", "riscv64": "riscv"}
    qemu_name = {"amd64": "x86_64", "arm64": "aarch64", "riscv64": "riscv64"}
    world_obj = args.world_obj or Path("/usr/obj/5BSD-hypertrace-validation/" +
                                       obj_name[args.arch])
    qemu = args.qemu or Path("/usr/local/bin/qemu-system-" +
                            qemu_name[args.arch])
    output.mkdir(parents=True)
    stage = output / "root"
    stage.mkdir()
    jobs = os.cpu_count() or 1
    target = {"amd64": ("amd64", "amd64"), "arm64": ("arm64", "aarch64"),
              "riscv64": ("riscv", "riscv64")}[args.arch]
    common = ["make", f"-j{jobs}", f"TARGET={target[0]}",
              f"TARGET_ARCH={target[1]}",
              f"DESTDIR={stage}", "NO_ROOT=yes"]
    world_env = {**os.environ, "MAKEOBJDIRPREFIX": str(world_obj)}
    kernel_env = {**os.environ, "MAKEOBJDIRPREFIX": str(args.kernel_obj)}
    run_logged(common + ["installworld"], output / "installworld.log",
               env=world_env)
    run_logged(common + ["KERNCONF=GENERIC", "installkernel"],
               output / "installkernel.log", env=kernel_env)
    run_logged(common + ["distribution"], output / "distribution.log",
               env=world_env)
    config = stage_config(stage, args.arch)
    metalog = output / "METALOG.sorted"
    normalize_metalog(stage, metalog, config)
    ufs = output / "root.ufs"
    image = output / "guest.img"
    run_logged(["makefs", "-t", "ffs", "-s", "6g", "-F", str(metalog),
                "-o", "version=2", str(ufs), str(stage)],
               output / "makefs.log")
    if args.arch == "amd64":
        partitions = ["-b", str(stage / "boot/pmbr"), "-p",
                      f"freebsd-boot:={stage / 'boot/gptboot'}"]
    else:
        esp = output / "esp"
        boot = esp / "EFI/BOOT"
        boot.mkdir(parents=True)
        boot_name = ("BOOTAA64.EFI" if args.arch == "arm64" else
                     "BOOTRISCV64.EFI")
        (boot / boot_name).write_bytes((stage / "boot/loader.efi").read_bytes())
        esp_image = output / "esp.img"
        run_logged(["makefs", "-t", "msdos", "-s", "64m", "-o",
                    "fat_type=32,sectors_per_cluster=1", str(esp_image),
                    str(esp)], output / "makefs-esp.log")
        partitions = ["-p", f"efi:={esp_image}"]
    run_logged(["mkimg", "-s", "gpt", "-f", "raw", *partitions, "-p",
                f"freebsd-ufs:={ufs}", "-o", str(image)],
               output / "mkimg.log")
    serial = output / "serial.log"
    vars_image = output / "edk2-riscv-vars.fd"
    if args.arch == "riscv64":
        shutil.copyfile("/usr/local/share/qemu/edk2-riscv-vars.fd", vars_image)
    platform = {
        "amd64": ["-machine", "q35", "-cpu", "max"],
        "arm64": ["-machine", "virt,gic-version=3", "-cpu", "cortex-a57",
                  "-bios", "/usr/local/share/qemu/edk2-aarch64-code.fd"],
        "riscv64": ["-machine", "virt,acpi=off,pflash0=pflash0,pflash1=pflash1",
                    "-cpu", "rv64", "-blockdev",
                    "node-name=pflash0,driver=file,read-only=on,"
                    "filename=/usr/local/share/qemu/edk2-riscv-code.fd",
                    "-blockdev", "node-name=pflash1,driver=file,filename=" +
                    str(vars_image)],
    }[args.arch]
    disk_device = ("virtio-blk-pci" if args.arch == "amd64" else
                   "virtio-blk-device")
    command = [str(qemu), "-L", "/usr/local/share/qemu", "-accel",
               "tcg,thread=multi", *platform,
               "-m", "2048", "-smp", "2", "-drive",
               f"file={image},format=raw,if=none,id=root,snapshot=on",
               "-device", f"{disk_device},drive=root,bootindex=1",
               "-display", "none", "-monitor", "none", "-serial",
               f"file:{serial}", "-no-reboot"]
    (output / "command.json").write_text(json.dumps(command, indent=2) + "\n")
    boot_timeout = 360 if args.arch == "riscv64" else 240
    qemu_error = None
    try:
        run_logged(command, output / "qemu.log", timeout=boot_timeout)
    except subprocess.TimeoutExpired:
        qemu_error = f"guest did not finish within {boot_timeout} seconds"
    except subprocess.CalledProcessError as error:
        qemu_error = f"QEMU exited with status {error.returncode}"
    text = serial.read_text(errors="replace") if serial.exists() else ""
    required = ("HYPERTRACE_VM_START", "HYPERTRACE_DTRACE_BEGIN_OK",
                "HYPERTRACE_DTRACE_EXIT=0", "HYPERTRACE_SYSCALL_PROBE_OK",
                "HYPERTRACE_SYSCALL_EXIT=0", "HYPERTRACE_IMMSTACK_PROBE_OK",
                "HYPERTRACE_IMMSTACK_EXIT=0",
                "HYPERTRACE_VM_DONE",
                "HYPERTRACE_DTRACE_NODE_OK", "HYPERTRACE_TRANSPORT_NODE_OK")
    missing = [marker for marker in required if marker not in text]
    match = re.search(r"^mbuf:\s+(\d+),", text, flags=re.MULTILINE)
    stack_output = (text.split("HYPERTRACE_IMMSTACK_PROBE_OK", 1)[1]
                    .split("HYPERTRACE_IMMSTACK_EXIT", 1)[0]
                    if "HYPERTRACE_IMMSTACK_PROBE_OK" in text else "")
    frames = re.findall(r"(?m)^[ \t]+([^ \t\r\n]+)\+0x[0-9a-fA-F]+[ \t\r]*$",
                        stack_output)
    named_frames = [name for name in frames if name != "??" and
                    not name.startswith("$")]
    result = {"passed": qemu_error is None and not missing and
              "panic:" not in text and
              match is not None and bool(named_frames),
              "missing": missing, "mbuf_zone_size": int(match.group(1)) if match else None,
              "immstack_frames": frames,
              "qemu_error": qemu_error,
              "serial": str(serial)}
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
