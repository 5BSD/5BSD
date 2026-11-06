# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

load(":installation_data.bzl", "D_SCRIPTS")

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":dtrace_shared",
        binary_name = name + "/libdtrace.so.2", debug_name = name + "/libdtrace.so.2.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libdtrace.so.2",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libdtrace.a", ["package=dtrace", "dev"], False),
        (":" + name + "_stripped", "/lib/libdtrace.so.2", ["package=dtrace"], False),
        (":" + name + "_symbols", "/usr/lib/debug/lib/libdtrace.so.2.debug", ["package=dtrace", "dbg"], False),
    ]
    for script in D_SCRIPTS:
        files.append((script, "/usr/lib/dtrace/" + script, ["package=dtrace"], False))
    files.append((":privileges", "/usr/lib/dtrace/priv.d", ["package=dtrace"], False))
    for source, destination in [
        ("//cddl/contrib/opensolaris:lib/libdtrace/common/dtrace.h", "/usr/include/dtrace.h"),
        ("//cddl/contrib/opensolaris:lib/libdtrace/common/dt_hypertrace.h", "/usr/include/dt_hypertrace.h"),
        ("//sys/cddl/contrib/opensolaris:uts/common/sys/dtrace.h", "/usr/include/sys/dtrace.h"),
        ("//sys/cddl/contrib/opensolaris:uts/common/sys/ctf_api.h", "/usr/include/sys/ctf_api.h"),
    ]:
        files.append((source, destination, ["package=dtrace", "dev"], False))
    bsd_compress(name = name + "_manual", src = "dtrace_fdopen.3",
        output = name + "/dtrace_fdopen.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
        redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/dtrace_fdopen.3.gz",
        select({"//tools/build/bazel/config:split_manpages_enabled": ["package=dtrace-man"], "//conditions:default": ["package=dtrace-dev"]}), True))
    entries = []
    for source, destination, tags, is_manual in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(manual = is_manual, name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libdtrace.so", target = "../../lib/libdtrace.so.2",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=dtrace", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
