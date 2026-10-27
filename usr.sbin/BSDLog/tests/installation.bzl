# SPDX-License-Identifier: BSD-2-Clause
# Native installation inventory shared by leaf and aggregate targets.
TESTDIR = "/usr/tests/usr.sbin/BSDLog"
ATF_PROGRAMS = ["bundle_test", "config_test", "evolution_test", "pool_fairness_test",
    "provider_test", "quota_test", "session_test", "storage_barrier_test", "storage_test",
    "store_fallback_test", "store_limit_test", "store_test"]
BINARIES = [p for p in ATF_PROGRAMS if p != "bundle_test"] + ["next_peer", "latency_bench"]
SOURCE_FIXTURES = {
    "//lib/liblogcmp:logcmp.c": "lib/liblogcmp/logcmp.c",
    "//lib/liblogcmp:logcmp_provider.d": "lib/liblogcmp/logcmp_provider.d",
    "//usr.sbin/BSDLog:BSDLog.8": "usr.sbin/BSDLog/BSDLog.8",
    "//usr.sbin/BSDLog:bsdlog_provider.d": "usr.sbin/BSDLog/bsdlog_provider.d",
    "//usr.sbin/BSDLog:capbundle/bsdlog.conf": "usr.sbin/BSDLog/capbundle/bsdlog.conf",
    "//usr.sbin/BSDLog:logcmp.c": "usr.sbin/BSDLog/logcmp.c",
}
SOURCE_DIRS = {TESTDIR + "/srctree/" + "/".join(dest.split("/")[:i]): True
    for dest in SOURCE_FIXTURES.values() for i in range(1, len(dest.split("/")))}
DIRECTORIES = ({d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsdlog-tests"]}'
        for d in [TESTDIR, TESTDIR + "/srctree", "/usr/share/licenses/bsdlog-tests", "/usr/share/licenses/bsdlog-tests/fuchsia"] + list(SOURCE_DIRS.keys())} |
        {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsdlog-tests","dbg"]}'
         for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/tests", "/usr/lib/debug/usr/tests/usr.sbin", "/usr/lib/debug" + TESTDIR]})
MANIFESTS = ["//usr.sbin/BSDLog/tests:install_" + p for p in BINARIES] + ["//usr.sbin/BSDLog/tests:install_extra"]
