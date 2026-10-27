# SPDX-License-Identifier: BSD-2-Clause
# Native installation inventory shared by leaf and aggregate targets.
TESTDIR = "/usr/tests/usr.sbin/BSDTrace"
ATF_PROGRAMS = ['bootstrap_test', 'bundle_test', 'evolution_test', 'lifecycle_test', 'policy_test', 'quota_test', 'session_test', 'shutdown_test']
BINARIES = [p for p in ATF_PROGRAMS if p != "bundle_test"] + ["next_peer", "latency_bench"]
SOURCE_FIXTURES = {'//lib/libtracecmp:tracecmp.c': 'lib/libtracecmp/tracecmp.c', '//lib/libtracecmp:tracecmp.fidl': 'lib/libtracecmp/tracecmp.fidl', '//lib/libtracecmp:tracecmp_provider.d': 'lib/libtracecmp/tracecmp_provider.d', '//usr.sbin/BSDTrace:bsdtrace_provider.d': 'usr.sbin/BSDTrace/bsdtrace_provider.d', '//usr.sbin/BSDTrace:tracecmp.c': 'usr.sbin/BSDTrace/tracecmp.c', '//usr.sbin/BSDTrace:tracecmp_policy.h': 'usr.sbin/BSDTrace/tracecmp_policy.h'}

SOURCE_DIRS = {TESTDIR + "/srctree/" + "/".join(dest.split("/")[:i]): True
    for dest in SOURCE_FIXTURES.values() for i in range(1, len(dest.split("/")))}
DIRECTORIES = ({d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsdtrace-provider-tests"]}'
        for d in [TESTDIR, TESTDIR + "/srctree", "/usr/share/licenses/bsdtrace-provider-tests", "/usr/share/licenses/bsdtrace-provider-tests/fuchsia"] + list(SOURCE_DIRS.keys())} |
        {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsdtrace-provider-tests","dbg"]}'
         for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/tests", "/usr/lib/debug/usr/tests/usr.sbin", "/usr/lib/debug" + TESTDIR]})
MANIFESTS = ["//usr.sbin/BSDTrace/tests:install_" + p for p in BINARIES] + ["//usr.sbin/BSDTrace/tests:install_extra"]
