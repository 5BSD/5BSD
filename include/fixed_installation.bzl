# SPDX-License-Identifier: BSD-2-Clause
"""Maintained fixed public header children; complete include parent is separate."""
load("//tools/build/bazel:bsd_public_headers.bzl", "public_header_installation")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//sys/i386/include:public_headers.bzl", "I386_COMPANION_HEADERS")
load("//sys/arm/include:public_headers.bzl", "ARM_COMPANION_HEADERS")

_GROUPS = {
    "arpa": ["ftp.h", "inet.h", "nameser.h", "nameser_compat.h", "tftp.h", "telnet.h"],
    "protocols": ["dumprestore.h", "routed.h", "rwhod.h", "talkd.h", "timed.h"],
    "ssp": ["poll.h", "random.h", "socket.h", "ssp.h", "signal.h", "stdio.h", "stdlib.h", "string.h", "strings.h", "uio.h", "unistd.h", "wchar.h"],
    "xlocale": ["_ctype.h", "_inttypes.h", "_langinfo.h", "_locale.h", "_monetary.h", "_stdio.h", "_stdlib.h", "_string.h", "_strings.h", "_time.h", "_uchar.h", "_wchar.h"],
}

def fixed_installation():
    for group, headers in _GROUPS.items():
        public_header_installation(name = group + "_install", directory = group,
            files = {group + "/" + header: header for header in headers})
    public_header_installation(name = "i386_install", directory = "i386", create_directory = True, directory_tags = ["package=clibs"],
        files = {"//sys/i386/include:" + header: header for header in I386_COMPANION_HEADERS})
    public_header_installation(name = "arm_install", directory = "arm", create_directory = True, directory_tags = ["package=clibs"],
        files = {"//sys/arm/include:" + header: header for header in ARM_COMPANION_HEADERS} | {"//lib/msun:arm/fenv.h": "fenv.h"})
    bsd_install_archive_set(name = "fixed_installation_archives",
        archives = [":" + group + "_install_archive" for group in _GROUPS] + select({
            "@platforms//cpu:x86_64": [":i386_install_archive"],
            "@platforms//cpu:aarch64": [":arm_install_archive"],
            "@platforms//cpu:riscv64": [],
        }), visibility = ["//visibility:public"])
