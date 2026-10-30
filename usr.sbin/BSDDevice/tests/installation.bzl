# SPDX-License-Identifier: BSD-2-Clause
TESTDIR = "/usr/tests/usr.sbin/BSDDevice"
ATF_PROGRAMS = ["evolution_test", "lifecycle_test", "policy_test", "provider_test", "quota_test"]
BINARIES = ATF_PROGRAMS + ["next_peer", "latency_bench"]
DIRECTORIES = ({d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsddevice-tests"]}'
    for d in [TESTDIR, "/usr/share/licenses/bsddevice-tests", "/usr/share/licenses/bsddevice-tests/fuchsia", "/usr/share/licenses/bsddevice-tests/libucl"]} |
    {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsddevice-tests","dbg"]}'
    for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/tests", "/usr/lib/debug/usr/tests/usr.sbin", "/usr/lib/debug" + TESTDIR]})
MANIFESTS = ["//usr.sbin/BSDDevice/tests:install_" + p for p in BINARIES] + ["//usr.sbin/BSDDevice/tests:install_extra"]
