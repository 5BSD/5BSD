# SPDX-License-Identifier: BSD-2-Clause
TESTDIR = "/usr/tests/lib/libtracecmp"
ATF_PROGRAMS = ["client_lifecycle_test", "tracecmp_test"]
BINARIES = ATF_PROGRAMS
DIRECTORIES = {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=libtracecmp-tests"]}'
    for d in [TESTDIR, "/usr/share/licenses/libtracecmp-tests", "/usr/share/licenses/libtracecmp-tests/fuchsia"]} | {
    d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=libtracecmp-tests","dbg"]}'
    for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/tests", "/usr/lib/debug/usr/tests/lib", "/usr/lib/debug" + TESTDIR]}
MANIFESTS = ["//lib/libtracecmp/tests:install_" + p for p in BINARIES] + ["//lib/libtracecmp/tests:install_extra"]
