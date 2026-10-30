# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

_HEADERS = ['atf-c++.hpp', 'atf-c++/build.hpp', 'atf-c++/check.hpp', 'atf-c++/macros.hpp', 'atf-c++/tests.hpp', 'atf-c++/utils.hpp']
_MANUAL_ALIASES = ['atf-c-api++.3']

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":atf_cxx_shared",
        binary_name = name + "/libprivateatf-c++.so.2", debug_name = name + "/libprivateatf-c++.so.2.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libprivateatf-c++.so.2",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libprivateatf-c++.a", ["package=atf", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libprivateatf-c++.so.2", ["package=atf", "lib"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libprivateatf-c++.so.2.debug", ["package=atf", "dbg"]),
    ]
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libprivateatf-c++.so", target = "libprivateatf-c++.so.2",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=atf", "dev"])
    entries.append(":" + name + "_link")
    for header in _HEADERS:
        target = name + "_header_" + header.replace("/", "_").replace(".", "_")
        bsd_install_file(name = target, src = "//contrib/atf:" + header,
            destination = "/usr/include/" + header, owner = "root", group = "wheel",
            mode = "0444", install_tags = ["package=atf", "dev"])
        entries.append(":" + target)
    tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=atf-man"], "//conditions:default": ["package=atf-dev"]})
    bsd_compress(name = name + "_manual", src = "//contrib/atf:atf-c++/atf-c++.3", output = name + "/atf-c++.3.gz",
        arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect",
        runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    bsd_install_file(name = name + "_man", src = ":" + name + "_manual", destination = "/usr/share/man/man3/atf-c++.3.gz",
        owner = "root", group = "wheel", mode = "0444", install_tags = tags)
    entries.append(":" + name + "_man")
    for alias in _MANUAL_ALIASES:
        target = name + "_man_" + alias.replace(".", "_")
        bsd_install_link(name = target, destination = "/usr/share/man/man3/" + alias + ".gz",
            target = "/usr/share/man/man3/atf-c++.3.gz", kind = "hardlink",
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
