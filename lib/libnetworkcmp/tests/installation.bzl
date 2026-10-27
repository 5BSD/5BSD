# SPDX-License-Identifier: BSD-2-Clause
TESTDIR = "/usr/tests/lib/libnetworkcmp"
ATF_PROGRAMS = ["client_lifecycle_test", "networkcmp_test", "state_client_test"]
BINARIES = ATF_PROGRAMS
DIRECTORIES = {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=libnetworkcmp-tests"]}'
    for d in [TESTDIR, "/usr/share/licenses/libnetworkcmp-tests", "/usr/share/licenses/libnetworkcmp-tests/fuchsia"]} | {
    d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=libnetworkcmp-tests","dbg"]}'
    for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/tests", "/usr/lib/debug/usr/tests/lib", "/usr/lib/debug" + TESTDIR]}
MANIFESTS = ["//lib/libnetworkcmp/tests:install_" + p for p in BINARIES] + ["//lib/libnetworkcmp/tests:install_extra"]
