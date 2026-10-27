# SPDX-License-Identifier: BSD-2-Clause
PROGRAMS = ["dependency_test", "pressure_test", "startup_test"]
TESTDIR = "/usr/tests/usr.sbin/BSDMemory"
MANIFESTS = ["//usr.sbin/BSDMemory/tests:install_" + n for n in PROGRAMS] + ["//usr.sbin/BSDMemory/tests:install_extra"]
DIRECTORIES = {TESTDIR: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsdmemory-tests"]}'} | {
    d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsdmemory-tests","dbg"]}'
    for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/tests", "/usr/lib/debug/usr/tests/usr.sbin", "/usr/lib/debug" + TESTDIR]}
