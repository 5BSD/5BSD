#!/usr/bin/env python3
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# check-stage-tests.py -- refuse a stage whose test programs come from more
# than one source checkout.
#
# usage: check-stage-tests.py STAGE_DIR [--allow ROOT]...
#
# A guest stage made by copying an older stage forward and reinstalling only
# some test directories carries the other directories' programs from the
# checkout that built the older stage.  An oracle that runs those suites
# (dq_tree_suites_test, dq_oracle_test) then compares another branch's tests
# (5bsd-issues 2026-11-18-guest-stage-stale-tests-sys-file-binaries.md).
#
# Every ELF file under STAGE_DIR/usr/tests is read for the source file names
# its code records (__FILE__ of ATF and assert(3) messages, NUL-terminated
# "/.../name.c" strings).  The checkout a name belongs to is the path before
# its first top-level source directory (tests, lib, sys, usr.bin, ...); a
# name in an object directory (MAKEOBJDIRPREFIX + checkout + /MACHINE.ARCH,
# for generated sources) is mapped back to its checkout.  One checkout for
# every program is clean.  More than one is STALE_TESTS (exit 3) unless each
# is named with --allow: a deliberate overlay of tests built from another
# checkout must say so.  This proves which checkout built each program, not
# which commit: a stage rebuilt from the same checkout at an older commit is
# not detected.
#
# Output: "TESTS_SRC_ROOT=ROOT programs=N" per checkout, most first, and for
# STALE_TESTS up to five programs of each minority checkout.  Exit 0 clean,
# 3 stale, 2 usage or no usr/tests.

import concurrent.futures
import os
import re
import sys

TOP = frozenset("""bin cddl contrib crypto gnu include kerberos5 krb5 lib
    libexec rescue sbin secure share stand sys tests tools usr.bin
    usr.sbin""".split())
SRC_NAME = re.compile(rb"\x00(/[A-Za-z0-9_.+/-]+\.(?:c|cc|cpp|cxx))\x00")
OBJ_MACHINE = re.compile(r"^(.*)/(?:amd64|arm64|i386|riscv|powerpc|arm)\.\w+$")


def checkout_of(path):
    parts = path.split("/")
    for i in range(1, len(parts) - 1):
        if parts[i + 1] in TOP:
            return "/".join(parts[:i + 1])
    return None


def main(argv):
    allow = []
    args = argv[1:]
    stage = None
    while args:
        a = args.pop(0)
        if a == "--allow" and args:
            allow.append(args.pop(0).rstrip("/"))
        elif stage is None and not a.startswith("-"):
            stage = a
        else:
            stage = None
            break
    if stage is None:
        print("usage: check-stage-tests.py STAGE_DIR [--allow ROOT]...",
              file=sys.stderr)
        return 2
    base = os.path.join(stage, "usr", "tests")
    if not os.path.isdir(base):
        print("check-stage-tests: no usr/tests in %s" % stage, file=sys.stderr)
        return 2

    def scan(fp):
        try:
            with open(fp, "rb") as fh:
                if fh.read(4) != b"\x7fELF":
                    return fp, None
                data = fh.read()
        except OSError:
            return fp, None
        roots = set()
        for m in SRC_NAME.findall(data):
            r = checkout_of(m.decode("ascii", "replace"))
            if r:
                roots.add(r)
        return fp, roots

    paths = []
    for d, _, files in os.walk(base):
        for f in files:
            fp = os.path.join(d, f)
            if not os.path.islink(fp) and os.path.isfile(fp):
                paths.append(fp)
    progs = {}          # program -> set of raw roots
    # The reads wait on the disk, not the CPU: overlap them.
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        for fp, roots in pool.map(scan, paths):
            if roots:
                progs[os.path.relpath(fp, stage)] = roots

    # Map object-directory roots to the checkout they were built from.
    plain = {r for rs in progs.values() for r in rs
             if not OBJ_MACHINE.match(r)}

    def canon(r):
        m = OBJ_MACHINE.match(r)
        if not m:
            return r
        obj = m.group(1)
        best = max((p for p in plain if obj.endswith(p)), key=len,
                   default=None)
        if best:
            return best
        return obj[len("/usr/obj"):] if obj.startswith("/usr/obj/") else obj

    by_root = {}
    for prog, rs in progs.items():
        for r in {canon(r) for r in rs}:
            by_root.setdefault(r, []).append(prog)
    order = sorted(by_root, key=lambda r: (-len(by_root[r]), r))
    for r in order:
        print("TESTS_SRC_ROOT=%s programs=%d" % (r, len(by_root[r])))
    if not order:
        print("TESTS_SRC_ROOT=none (no test program names a source file)")
        return 0
    unexpected = [r for r in order if r not in allow] if allow else order[1:]
    if not unexpected:
        return 0
    for r in unexpected:
        for prog in sorted(by_root[r])[:5]:
            print("STALE_TESTS: %s names %s" % (prog, r))
    if allow:
        print("STALE_TESTS: checkouts not in TESTS_SRC_ROOTS (%s): %s"
              % (" ".join(allow), " ".join(unexpected)))
    else:
        print("STALE_TESTS: the stage's test programs come from %d "
              "checkouts; reinstall usr/tests from the branch under test "
              "(or a fresh stage), or name every checkout in "
              "TESTS_SRC_ROOTS for a deliberate overlay" % len(order))
    return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv))
