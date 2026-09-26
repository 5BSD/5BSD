#!/usr/bin/env python3
"""Bounded regular-file fio measurements of the currently running kernel."""
import argparse
import json
from pathlib import Path
import platform
import resource
import subprocess
import time

def capture(args):
    p = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return {"exit": p.returncode, "output": p.stdout.strip()}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fio", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    data = out / "workload.data"
    metadata = {"kernel": platform.uname()._asdict(), "started": time.time(), "memlock_limit_bytes": resource.getrlimit(resource.RLIMIT_MEMLOCK), "scope": "Installed kernel, regular file, short warm-cache measurements; not candidate-kernel or raw-device qualification", "machine": capture(["sysctl", "hw.model", "hw.ncpu", "hw.physmem", "debug.witness.watch"]), "load": capture(["uptime"]), "filesystem": capture(["df", "-T", str(out)]), "runs": []}
    fio = str(a.fio.resolve())
    common = [fio, "--filename=" + str(data), "--size=64m", "--bs=4k", "--direct=1", "--fallocate=none", "--eta=never", "--output-format=json", "--clocksource=clock_gettime", "--lat_percentiles=1"]
    def run(name, args):
        before = capture(["sysctl", "-n", "kern.squeue.submitted"])
        cmd = common + ["--name=" + name] + args
        begin = time.time()
        try:
            result = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
            status, text = result.returncode, result.stdout
        except subprocess.TimeoutExpired as e:
            status, text = 124, (e.stdout or b"").decode(errors="replace")
        (out / (name + ".json")).write_text(text)
        after = capture(["sysctl", "-n", "kern.squeue.submitted"])
        record = {"name": name, "command": cmd, "exit": status, "seconds": time.time() - begin, "submitted_before": before, "submitted_after": after}
        try:
            report = json.loads(text[text.index("{"):])
            record["jobs"] = [{k: job[k] for k in ["error", "read", "write", "usr_cpu", "sys_cpu", "iodepth_level"]} for job in report["jobs"]]
        except (ValueError, KeyError):
            record["parse_error"] = True
        metadata["runs"].append(record)
        (out / "summary.json").write_text(json.dumps(metadata, indent=2) + "\n")
        print(name, status, flush=True)
        return status
    failed = False
    try:
        if run("prepare", ["--ioengine=io_uring", "--iodepth=16", "--rw=write", "--verify=crc32c", "--do_verify=1", "--verify_fatal=1"]):
            return 1
        for repeat in range(1, 4):
            for engine, depth, extra in [("psync", 1, []), ("io_uring", 1, []), ("io_uring", 8, []), ("io_uring", 32, []), ("io_uring", 32, ["--sqthread_poll=1", "--registerfiles=1"])]:
                name = f"{engine}-q{depth}-{'sqpoll-' if extra else ''}r{repeat}"
                failed |= bool(run(name, ["--ioengine=" + engine, "--iodepth=" + str(depth), "--rw=randrw", "--rwmixread=70", "--time_based=1", "--runtime=3", "--ramp_time=1", "--randrepeat=1"] + extra))
        return 1 if failed else 0
    finally:
        data.unlink(missing_ok=True)
        metadata["finished"] = time.time()
        metadata["resources_after"] = capture(["sysctl", "kern.squeue.live_requests", "kern.squeue.registered_files", "kern.squeue.issuer_refs", "kern.squeue.issuer_tokens", "kern.squeue.wired_pages"])
        (out / "summary.json").write_text(json.dumps(metadata, indent=2) + "\n")

if __name__ == "__main__":
    raise SystemExit(main())
