# SPDX-License-Identifier: BSD-2-Clause
TESTDIR = "/usr/tests/usr.sbin/BSDNamespace"
ATF_PROGRAMS = ["evolution_test", "jailname_test", "provider_test", "reclaim_test"]
BINARIES = ATF_PROGRAMS + ["next_peer", "latency_bench"]
DIRECTORIES = ({d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsdnamespace-tests"]}'
    for d in [TESTDIR, "/usr/share/licenses/bsdnamespace-tests", "/usr/share/licenses/bsdnamespace-tests/fuchsia"]} |
    {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsdnamespace-tests","dbg"]}'
    for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/tests", "/usr/lib/debug/usr/tests/usr.sbin", "/usr/lib/debug" + TESTDIR]})
MANIFESTS = ["//usr.sbin/BSDNamespace/tests:install_" + p for p in BINARIES] + ["//usr.sbin/BSDNamespace/tests:install_extra"]
