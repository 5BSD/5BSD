# SPDX-License-Identifier: BSD-2-Clause
# Native installation inventory shared by leaf and aggregate targets.
TESTDIR = "/usr/tests/usr.sbin/BSDCrypto"
ATF_PROGRAMS = ['bundle_test', 'evolution_test', 'lifecycle_test', 'policy_test', 'provider_test', 'quota_test']
BINARIES = [p for p in ATF_PROGRAMS if p != "bundle_test"] + ["next_peer", "latency_bench"]
SOURCE_FIXTURES = {'//usr.sbin/BSDCrypto:Makefile': 'usr.sbin/BSDCrypto/Makefile', '//usr.sbin/BSDCrypto:bsdcrypto.c': 'usr.sbin/BSDCrypto/bsdcrypto.c'}

SOURCE_DIRS = {TESTDIR + "/srctree/" + "/".join(dest.split("/")[:i]): True
    for dest in SOURCE_FIXTURES.values() for i in range(1, len(dest.split("/")))}
DIRECTORIES = ({d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsdcrypto-tests"]}'
        for d in [TESTDIR, TESTDIR + "/srctree", "/usr/share/licenses/bsdcrypto-tests", "/usr/share/licenses/bsdcrypto-tests/fuchsia"] + list(SOURCE_DIRS.keys())} |
        {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsdcrypto-tests","dbg"]}'
         for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/tests", "/usr/lib/debug/usr/tests/usr.sbin", "/usr/lib/debug" + TESTDIR]})
MANIFESTS = ["//usr.sbin/BSDCrypto/tests:install_" + p for p in BINARIES] + ["//usr.sbin/BSDCrypto/tests:install_extra"]
