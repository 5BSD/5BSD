# SPDX-License-Identifier: BSD-2-Clause
# Native installation inventory shared by leaf and aggregate targets.
TESTDIR = "/usr/tests/usr.sbin/BSDNetwork"
ATF_PROGRAMS = ['bundle_test', 'coalesce_test', 'config_test', 'connect_deadline_test', 'evolution_test', 'pf_test', 'policy_test', 'provider_test', 'resolver_recovery_test', 'resolver_test', 'state_plane_test', 'state_sampler_test', 'state_test', 'worker_test']
BINARIES = [p for p in ATF_PROGRAMS if p != "bundle_test"] + ["next_peer", "latency_bench"]
SOURCE_FIXTURES = {'//usr.sbin/BSDFilesystem:bsdfilesystem.ucl': 'usr.sbin/BSDFilesystem/bsdfilesystem.ucl', '//usr.sbin/BSDNetwork:capbundle/bsdnetwork.conf': 'usr.sbin/BSDNetwork/capbundle/bsdnetwork.conf', '//usr.sbin/BSDNetwork:bsdnetwork_provider.d': 'usr.sbin/BSDNetwork/bsdnetwork_provider.d', '//usr.sbin/BSDNetwork:networkcmp.c': 'usr.sbin/BSDNetwork/networkcmp.c', '//usr.sbin/BSDNetwork:resolver.c': 'usr.sbin/BSDNetwork/resolver.c'}

SOURCE_DIRS = {TESTDIR + "/srctree/" + "/".join(dest.split("/")[:i]): True
    for dest in SOURCE_FIXTURES.values() for i in range(1, len(dest.split("/")))}
DIRECTORIES = ({d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsdnetwork-tests"]}'
        for d in [TESTDIR, TESTDIR + "/srctree", "/usr/share/licenses/bsdnetwork-tests", "/usr/share/licenses/bsdnetwork-tests/fuchsia"] + list(SOURCE_DIRS.keys())} |
        {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsdnetwork-tests","dbg"]}'
         for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/tests", "/usr/lib/debug/usr/tests/usr.sbin", "/usr/lib/debug" + TESTDIR]})
MANIFESTS = ["//usr.sbin/BSDNetwork/tests:install_" + p for p in BINARIES] + ["//usr.sbin/BSDNetwork/tests:install_extra"]
