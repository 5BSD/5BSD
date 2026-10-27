# SPDX-License-Identifier: BSD-2-Clause
# Native installation inventory shared by leaf and aggregate targets.
TESTDIR = "/usr/tests/usr.sbin/BSDNotify"
ATF_PROGRAMS = ["broker_test", "bundle_test", "dispatcher_test", "policy_test", "session_test", "transport_test"]
BINARIES = [p for p in ATF_PROGRAMS if p != "bundle_test"] + ["next_peer", "latency_bench"]
SOURCE_FIXTURES = {
    "//cddl/usr.sbin/bsdinstruments/profiles:capability-services.d": "cddl/usr.sbin/bsdinstruments/profiles/capability-services.d",
    "//lib/libnotify:notify.c": "lib/libnotify/notify.c",
    "//lib/libnotify:notify_protocol.h": "lib/libnotify/notify_protocol.h",
    "//lib/libnotify:notify_provider.d": "lib/libnotify/notify_provider.d",
    "//usr.sbin/BSDAudit:auditcmp_policy.c": "usr.sbin/BSDAudit/auditcmp_policy.c",
    "//usr.sbin/BSDNotify:Makefile": "usr.sbin/BSDNotify/Makefile",
    "//usr.sbin/BSDNotify:bsdnotify.c": "usr.sbin/BSDNotify/bsdnotify.c",
    "//usr.sbin/BSDNotify:bsdnotify_probes.h": "usr.sbin/BSDNotify/bsdnotify_probes.h",
    "//usr.sbin/BSDNotify:bsdnotify_provider.d": "usr.sbin/BSDNotify/bsdnotify_provider.d",
    "//usr.sbin/BSDNotify:capbundle/bsdnotify.conf": "usr.sbin/BSDNotify/capbundle/bsdnotify.conf",
    "//usr.sbin/BSDNotify:capbundle/bsdnotify.ucl": "usr.sbin/BSDNotify/capbundle/bsdnotify.ucl",
    "//usr.sbin/BSDNotify:policy.c": "usr.sbin/BSDNotify/policy.c",
    "//usr.sbin/BSDNotify:policy.h": "usr.sbin/BSDNotify/policy.h",
    "//usr.sbin/switchboard:svc_proto.c": "usr.sbin/switchboard/svc_proto.c"
}
SOURCE_DIRS = {TESTDIR + "/srctree/" + "/".join(dest.split("/")[:i]): True
    for dest in SOURCE_FIXTURES.values() for i in range(1, len(dest.split("/")))}
DIRECTORIES = ({d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsdnotify-tests"]}'
        for d in [TESTDIR, TESTDIR + "/srctree", "/usr/share/licenses/bsdnotify-tests", "/usr/share/licenses/bsdnotify-tests/fuchsia"] + list(SOURCE_DIRS.keys())} |
        {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsdnotify-tests","dbg"]}'
         for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/tests", "/usr/lib/debug/usr/tests/usr.sbin", "/usr/lib/debug" + TESTDIR]})
MANIFESTS = ["//usr.sbin/BSDNotify/tests:install_" + p for p in BINARIES] + ["//usr.sbin/BSDNotify/tests:install_extra"]
