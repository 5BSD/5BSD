# SPDX-License-Identifier: BSD-2-Clause
TESTDIR = "/usr/tests/usr.sbin/BSDVM"
ATF_PROGRAMS = ["evolution_test", "lifecycle_test", "provider_test", "registry_test", "serve_test"]
BINARIES = ATF_PROGRAMS + ["next_peer", "latency_bench"]
DIRECTORIES = {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=waspnest-tests"]}'
    for d in [TESTDIR, "/usr/share/licenses/waspnest-tests", "/usr/share/licenses/waspnest-tests/fuchsia"]} | {
    d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=waspnest-tests","dbg"]}'
    for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/tests", "/usr/lib/debug/usr/tests/usr.sbin", "/usr/lib/debug" + TESTDIR]}
MANIFESTS = ["//usr.sbin/BSDVM/tests:install_" + p for p in BINARIES] + ["//usr.sbin/BSDVM/tests:install_extra"]
