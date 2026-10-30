# SPDX-License-Identifier: BSD-2-Clause
# Native installation inventory shared by leaf and aggregate targets.
TESTDIR = "/usr/tests/usr.sbin/BSDSysctl"
ATF_PROGRAMS = ["config_test", "evolution_test", "interfaces_test", "observability_test", "provider_test", "reactor_test"]
BINARIES = [p for p in ATF_PROGRAMS if p != "observability_test"] + ["next_peer", "latency_bench"]
SOURCE_FIXTURES = {
    "//usr.sbin/BSDSysctl/capbundle:sysctl.conf": "usr.sbin/BSDSysctl/capbundle/sysctl.conf",
    "//cddl/usr.sbin/bsdinstruments/profiles:capability-services.d": "cddl/usr.sbin/bsdinstruments/profiles/capability-services.d",
    "//usr.sbin/BSDSysctl:bsdsysctl.c": "usr.sbin/BSDSysctl/bsdsysctl.c",
    "//usr.sbin/BSDSysctl:bsdsysctl_provider.d": "usr.sbin/BSDSysctl/bsdsysctl_provider.d"
}
SOURCE_DIRS = {TESTDIR + "/srctree/" + "/".join(dest.split("/")[:i]): True
    for dest in SOURCE_FIXTURES.values() for i in range(1, len(dest.split("/")))}
DIRECTORIES = ({d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=libsysctlcmp-tests"]}'
        for d in [TESTDIR, TESTDIR + "/srctree", "/usr/share/licenses/libsysctlcmp-tests", "/usr/share/licenses/libsysctlcmp-tests/fuchsia-bsdsysctl", "/usr/share/licenses/libsysctlcmp-tests/libucl-bsdsysctl"] + list(SOURCE_DIRS.keys())} |
        {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=libsysctlcmp-tests","dbg"]}'
         for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/tests", "/usr/lib/debug/usr/tests/usr.sbin", "/usr/lib/debug" + TESTDIR]})
MANIFESTS = ["//usr.sbin/BSDSysctl/tests:install_" + p for p in BINARIES] + ["//usr.sbin/BSDSysctl/tests:install_extra"]
