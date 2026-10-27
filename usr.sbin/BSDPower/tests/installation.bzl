# SPDX-License-Identifier: BSD-2-Clause
PROGRAMS = ["config_test", "evolution_test", "lease_test", "provider_test", "reactor_test", "next_peer", "latency_bench"]
MANIFESTS = ["//usr.sbin/BSDPower/tests:install_" + n for n in PROGRAMS] + ["//usr.sbin/BSDPower/tests:install_extra"]
DIRECTORIES = {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=runtime-tests"]}'
    for d in ["/usr/tests/usr.sbin/BSDPower", "/usr/share/licenses/bsdpower-tests", "/usr/share/licenses/bsdpower-tests/fuchsia", "/usr/share/licenses/bsdpower-tests/libucl"]} | {
    d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=runtime-tests","dbg"]}'
    for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/tests", "/usr/lib/debug/usr/tests/usr.sbin", "/usr/lib/debug/usr/tests/usr.sbin/BSDPower"]}
