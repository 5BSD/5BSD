# SPDX-License-Identifier: BSD-2-Clause
"""Maintained public include aliases; link text is relative installed ABI policy."""
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_link", "bsd_install_manifest")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")

def alias_installation():
    entries = []
    for directory, headers in [
        ("sys", ["aio.h", "errno.h", "fcntl.h", "linker_set.h", "poll.h", "stdatomic.h", "stdint.h", "syslog.h", "ucontext.h", "_semaphore.h", "stdarg.h"]),
        ("machine", ["float.h", "floatingpoint.h"]),
    ]:
        for header in headers:
            name = "include_alias_" + header
            bsd_install_link(name = name, destination = "/usr/include/" + header,
                target = directory + "/" + header, kind = "symlink", owner = "root", group = "wheel",
                mode = "0755", install_tags = ["package=clibs", "dev"])
            entries.append(":" + name)
    bsd_install_link(name = "library_include_alias", destination = "/usr/lib/include", target = "../../usr/include",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=clibs"])
    bsd_install_manifest(name = "aliases_manifest", entries = [":library_include_alias"] + select({
        "//tools/build/bazel/config:includes_enabled": entries, "//conditions:default": [],
    }))
    bsd_install_archive(name = "aliases_archive", manifests = [":aliases_manifest"],
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr", "//etc/mtree:BSD.include.dist": "/usr/include"},
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"], visibility = ["//visibility:public"])
