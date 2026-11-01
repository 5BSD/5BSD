# SPDX-License-Identifier: BSD-2-Clause
"""Source payloads and directory ownership shared by installer archives."""
load("//docs/book:sources.bzl", "BOOK_FILES")

_HEADERS = ["capsicum.h", "event.h", "fcntl.h", "file.h", "filedesc.h", "mbuf.h", "procctl.h", "procdesc.h", "ptrace.h", "socket.h", "sysent.h", "un.h", "user.h", "wait.h"]
TEST_SOURCES = {"//docs/book:src/" + path: "docs/book/src/" + path for path in BOOK_FILES} | {
    "//sys/sys:" + name: "sys/sys/" + name for name in _HEADERS
} | {
    "//docs/book:tools/check-book.sh": "docs/book/tools/check-book.sh",
    "//release/tools:vmimage.subr": "release/tools/vmimage.subr",
    "//sys/kern:syscalls.master": "sys/kern/syscalls.master",
    "//usr.sbin/bsdinstall:bsdinstall.8": "usr.sbin/bsdinstall/bsdinstall.8",
}

_DIRECTORIES = {"/usr/tests/usr.sbin/bsdinstall": True, "/usr/tests/usr.sbin/bsdinstall/srctree": True} | {
    "/usr/tests/usr.sbin/bsdinstall/srctree/" + "/".join(path.split("/")[:index]): True
    for path in TEST_SOURCES.values() for index in range(1, len(path.split("/")))
}

TEST_DIRECTORY_RECORDS = {
    path: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsdinstall-tests"]}'
    for path in _DIRECTORIES
}
