#!/usr/bin/env python3
"""Compare captured guest logs without promoting skips or incomplete runs to passes."""
import argparse
import collections
import json
from pathlib import Path
import re

def read(path):
    return path.read_text(errors="replace").replace("\r", "")

def parse(text):
    cases = {}
    for match in re.finditer(r"^UPSTREAM_BEGIN (\S+)\n(.*?)^UPSTREAM_RESULT (\S+) (\d+)\s*$", text, re.M | re.S):
        name, output, end, code = match.groups()
        if name != end or "UPSTREAM_BEGIN " in output or name in cases:
            raise ValueError("Malformed or duplicate test result: " + name)
        code = int(code)
        cases[name] = {"exit": code, "status": "pass" if code == 0 else "skip" if code == 77 else "timeout" if code == 124 else "fail", "output": output.strip(), "internal_skip_message": bool(re.search(r"skip", output, re.I))}
    return {"complete": "\nUPSTREAM_DONE\n" in text, "cases": cases, "counts": dict(collections.Counter(x["status"] for x in cases.values())), "quarantined": re.findall(r"^UPSTREAM_QUARANTINE (.*)$", text, re.M), "fio": {n: int(c) for n, c in re.findall(r"^FIO_RESULT (\S+) (\d+)$", text, re.M)}, "resources": {n: int(c) for n, c in re.findall(r"^kern.squeue.(live_requests|registered_files|issuer_refs|issuer_tokens|wired_pages): (\d+)$", text, re.M)}}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--candidate", type=Path, required=True)
    p.add_argument("--oracle", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--cases", type=Path, default=Path(__file__).with_name("cases.txt"))
    a = p.parse_args()
    expected = set(a.cases.read_text().split())
    result = {"candidate": parse(read(a.candidate)), "oracle": parse(read(a.oracle))}
    for side in ["candidate", "oracle"]:
        result[side]["unexecuted"] = sorted(expected - result[side]["cases"].keys())
    result["linux_pass_candidate_nonpass"] = [name for name in sorted(expected) if result["oracle"]["cases"].get(name, {}).get("status") == "pass" and result["candidate"]["cases"].get(name, {}).get("status") != "pass"]
    result["qualification_passed"] = all(result[s]["complete"] and not result[s]["unexecuted"] and all(c["status"] == "pass" for c in result[s]["cases"].values()) for s in ["candidate", "oracle"])
    a.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({s: result[s]["counts"] for s in ["candidate", "oracle"]}))
    return 0 if result["qualification_passed"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
