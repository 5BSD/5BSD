# SPDX-License-Identifier: BSD-2-Clause
TESTDIR = "/usr/tests/lib/liboes"
ATF_PROGRAMS = ["ownership_test", "path_test", "broker_protocol_test", "broker_client_test"]
DIRECTORIES = {TESTDIR: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=oes"]}'} | {
    d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=oes","dbg"]}'
    for d in ["/usr/lib/debug/usr/tests", "/usr/lib/debug/usr/tests/lib", "/usr/lib/debug" + TESTDIR]}
MANIFESTS = ["//lib/liboes/tests:install_" + p for p in ATF_PROGRAMS] + ["//lib/liboes/tests:install_extra"]
