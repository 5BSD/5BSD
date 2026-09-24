#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Validate network uevents in a pre-staged disposable amd64 guest."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--image", required=True)
parser.add_argument("--output", required=True)
parser.add_argument("--cpus", type=int, default=4)
parser.add_argument("--qemu", default="qemu-system-x86_64")
parser.add_argument("--firmware-dir")
parser.add_argument("--timeout", type=int, default=1800)
args = parser.parse_args()
output = Path(args.output)
output.mkdir(parents=True, exist_ok=True)
log = output / "console.log"
command = [args.qemu]
if args.firmware_dir:
    command += ["-L", args.firmware_dir]
command += [
    "-accel", "tcg,thread=multi", "-m", "1536", "-smp", str(args.cpus),
    "-nic", "user,model=virtio-net-pci,restrict=on", "-display", "none",
    "-monitor", "none", "-serial", "stdio", "-no-reboot", "-machine", "q35",
    "-cpu", "max", "-drive",
    f"file={Path(args.image).resolve()},format=raw,if=virtio,snapshot=on",
]
diagnostics = r"panic:|Fatal trap|lock order reversal|non-sleepable locks held"
with log.open("wb") as stream:
    process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT,
                               env=os.environ.copy())
    deadline = time.monotonic() + args.timeout
    try:
        while process.poll() is None:
            text = log.read_text(errors="replace")
            if time.monotonic() > deadline or re.search(diagnostics, text):
                process.kill()
                break
            time.sleep(2)
        process.wait()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()

text = log.read_text(errors="replace").replace("\r", "")
users = ("root", "unprivileged")
rows = re.findall(r"^UEVENT_RESULT (root|unprivileged) (raw|dgram) (\d+)$", text, re.M)
expected = {(uid, kind, "0") for uid in users for kind in ("raw", "dgram")}
isolation = re.findall(r"^UEVENT_ISOLATION (\w+) (root|unprivileged) (\d+)$", text, re.M)
expected_isolation = {
    (mode, uid, "0") for uid in users for mode in
    ("host_from_vnet", "vnet_from_host", "shared_from_host", "same_vnet", "same_host")
}
overflow = re.findall(r"^UEVENT_OVERFLOW (root|unprivileged) (\d+)$", text, re.M)
names = re.findall(r"^UEVENT_NAMES (root|unprivileged) (\d+)$", text, re.M)
counts = re.findall(r"^UEVENT_SOCKET_COUNTS (\d+) (\d+)$", text, re.M)
lifecycle = re.findall(r"^UEVENT_LIFECYCLE (\d+)$", text, re.M)
passed = (
    process.returncode == 0 and len(rows) == 4 and set(rows) == expected
    and len(isolation) == 10 and set(isolation) == expected_isolation
    and len(overflow) == 2 and set(overflow) == {(uid, "0") for uid in users}
    and len(names) == 2 and set(names) == {(uid, "0") for uid in users}
    and lifecycle == ["0"] and len(counts) == 1 and counts[0][0] == counts[0][1]
    and len(re.findall(r"^UEVENT_PACKET ", text, re.M)) == 12
    and len(re.findall(r"^UEVENT_PASS ", text, re.M)) == 4
    and all(marker in text for marker in (
        "UEVENT_DONE", "UEVENT_EXIT 0", "Powering system off", "all pools are healthy"))
    and not re.search(diagnostics, text)
)
result = dict(passed=passed, command=command, rows=rows, isolation=isolation,
              overflow=overflow, names=names, lifecycle=lifecycle,
              socket_counts=counts, exit_code=process.returncode)
(output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
print("Linux network device events:", "PASS" if passed else "FAIL")
raise SystemExit(0 if passed else 1)
