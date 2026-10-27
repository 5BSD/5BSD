# SPDX-License-Identifier: BSD-2-Clause
TESTDIR = "/usr/tests/lib/libdevicecmp"
ATF_PROGRAMS = ["client_protocol_test", "devicecmp_api_test"]
BINARIES = ATF_PROGRAMS
DIRECTORIES = {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=libdevicecmp-tests"]}'
    for d in [TESTDIR, "/usr/share/licenses/libdevicecmp-tests", "/usr/share/licenses/libdevicecmp-tests/fuchsia"]} | {
    d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=libdevicecmp-tests","dbg"]}'
    for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/tests", "/usr/lib/debug/usr/tests/lib", "/usr/lib/debug" + TESTDIR]}
MANIFESTS = ["//lib/libdevicecmp/tests:install_" + p for p in BINARIES] + ["//lib/libdevicecmp/tests:install_extra"]
