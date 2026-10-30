# SPDX-License-Identifier: BSD-2-Clause
load(":source_fixtures.bzl", "SOURCE_FIXTURES")
# Derive every fixture ancestor from the declared payload, matching srctree.mk.
_FIXTURE_DIRS = {"/usr/tests/usr.sbin/switchboard/" + "/".join(destination.split("/")[:depth]): True
    for destination in SOURCE_FIXTURES.values() for depth in range(1, len(destination.split("/")))}
TEST_DIRECTORIES = ({d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=switchboard-tests"]}'
        for d in ["/usr/tests/usr.sbin/switchboard"] + list(_FIXTURE_DIRS.keys())} |
        {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=switchboard-tests","dbg"]}'
        for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/tests", "/usr/lib/debug/usr/tests/usr.sbin", "/usr/lib/debug/usr/tests/usr.sbin/switchboard"]})
