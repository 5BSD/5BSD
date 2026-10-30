# SPDX-License-Identifier: BSD-2-Clause
TEST_DIRECTORIES = ({"/usr/tests/usr.sbin/capsule": '{"owner":"root","group":"wheel","mode":"0755","tags":["package=capsule-tests"]}'} |
        {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=capsule-tests","dbg"]}' for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/tests", "/usr/lib/debug/usr/tests/usr.sbin", "/usr/lib/debug/usr/tests/usr.sbin/capsule"]})
