# SPDX-License-Identifier: BSD-2-Clause
TESTDIR = "/usr/tests/usr.sbin/BSDExtension"
ATF_PROGRAMS = ["allowlist_test", "drivers_test", "evolution_test", "inherited_session_test", "policy_test", "provider_test", "reclaim_test", "startup_test"]
BINARIES = [p for p in ATF_PROGRAMS if p != "startup_test"] + ["next_peer", "latency_bench"]
DIRECTORIES = ({d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsdextension-tests"]}'
    for d in [TESTDIR, "/usr/share/licenses/bsdextension-tests", "/usr/share/licenses/bsdextension-tests/fuchsia"]} |
    {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsdextension-tests","dbg"]}'
    for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/tests", "/usr/lib/debug/usr/tests/usr.sbin", "/usr/lib/debug" + TESTDIR]})
MANIFESTS = ["//usr.sbin/BSDExtension/tests:install_" + p for p in BINARIES] + ["//usr.sbin/BSDExtension/tests:install_extra"]
