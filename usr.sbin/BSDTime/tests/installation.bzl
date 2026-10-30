# SPDX-License-Identifier: BSD-2-Clause
PROGRAMS = ["config_test", "gate_test", "provider_test", "resource_soak"]
MANIFESTS = ["//usr.sbin/BSDTime/tests:install_" + n for n in PROGRAMS] + ["//usr.sbin/BSDTime/tests:install_extra"]
DIRECTORIES = {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsdtime-tests"]}'
    for d in ["/usr/tests/usr.sbin/BSDTime", "/usr/share/licenses/bsdtime-tests", "/usr/share/licenses/bsdtime-tests/fuchsia", "/usr/share/licenses/bsdtime-tests/libucl"]} | {
    d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsdtime-tests","dbg"]}'
    for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/tests", "/usr/lib/debug/usr/tests/usr.sbin", "/usr/lib/debug/usr/tests/usr.sbin/BSDTime"]}
