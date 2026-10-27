# SPDX-License-Identifier: BSD-2-Clause
TESTDIR = "/usr/tests/lib/libcryptocmp"
ATF_PROGRAMS = ["client_protocol_test", "cryptocmp_api_test"]
BINARIES = ATF_PROGRAMS
DIRECTORIES = {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=libcryptocmp-tests"]}'
    for d in [TESTDIR, "/usr/share/licenses/libcryptocmp-tests", "/usr/share/licenses/libcryptocmp-tests/fuchsia"]} | {
    d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=libcryptocmp-tests","dbg"]}'
    for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/tests", "/usr/lib/debug/usr/tests/lib", "/usr/lib/debug" + TESTDIR]}
MANIFESTS = ["//lib/libcryptocmp/tests:install_" + p for p in BINARIES] + ["//lib/libcryptocmp/tests:install_extra"]
