# SPDX-License-Identifier: BSD-2-Clause
# Native installation inventory shared by leaf and aggregate targets.
TESTDIR = "/usr/tests/usr.sbin/BSDAudit"
ATF_PROGRAMS = ["bootstrap_test", "bundle_test", "evolution_test", "lifecycle_test", "policy_test", "rate_test", "session_test", "shutdown_test", "submit_test"]
BINARIES = [p for p in ATF_PROGRAMS if p != "bundle_test"] + ["next_peer", "latency_bench"]
SOURCE_FIXTURES = {
    "//contrib/openbsm:etc/audit_event": "contrib/openbsm/etc/audit_event",
    "//contrib/openbsm:libbsm/bsm_wrappers.c": "contrib/openbsm/libbsm/bsm_wrappers.c",
    "//sys/bsm:audit_kevents.h": "sys/bsm/audit_kevents.h",
    "//sys/kern:syscalls.master": "sys/kern/syscalls.master",
    "//sys/security/audit:audit_syscalls.c": "sys/security/audit/audit_syscalls.c",
    "//usr.sbin/BSDAudit:auditcmp.c": "usr.sbin/BSDAudit/auditcmp.c",
    "//usr.sbin/BSDAudit:auditcmp_policy.c": "usr.sbin/BSDAudit/auditcmp_policy.c",
    "//usr.sbin/BSDAudit:auditcmp_policy.h": "usr.sbin/BSDAudit/auditcmp_policy.h",
    "//usr.sbin/BSDAudit:bsdaudit_provider.d": "usr.sbin/BSDAudit/bsdaudit_provider.d",
    "//usr.sbin/BSDAudit:capbundle/bsdaudit.ucl": "usr.sbin/BSDAudit/capbundle/bsdaudit.ucl"
}
SOURCE_DIRS = {TESTDIR + "/srctree/" + "/".join(dest.split("/")[:i]): True
    for dest in SOURCE_FIXTURES.values() for i in range(1, len(dest.split("/")))}
DIRECTORIES = ({d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsdaudit-tests"]}'
        for d in [TESTDIR, TESTDIR + "/srctree", "/usr/share/licenses/bsdaudit-tests", "/usr/share/licenses/bsdaudit-tests/fuchsia"] + list(SOURCE_DIRS.keys())} |
        {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsdaudit-tests","dbg"]}'
         for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/tests", "/usr/lib/debug/usr/tests/usr.sbin", "/usr/lib/debug" + TESTDIR]})
MANIFESTS = ["//usr.sbin/BSDAudit/tests:install_" + p for p in BINARIES] + ["//usr.sbin/BSDAudit/tests:install_extra"]
