# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

MANUAL_ALIASES = ['service_enter_namespace', 'service_enter_namespace_ex', 'service_destroy_namespace', 'service_namespace_info']

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":namespacecmp_shared",
        binary_name = name + "/libnamespacecmp.so.1", debug_name = name + "/libnamespacecmp.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libnamespacecmp.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        ("namespacecmp.h", "/usr/include/namespacecmp.h", ["package=libnamespacecmp", "dev"], False),

        (":static_archive", "/usr/lib/libnamespacecmp.a", ["package=libnamespacecmp", "dev"], False),
        (":" + name + "_stripped", "/usr/lib/libnamespacecmp.so.1", ["package=libnamespacecmp"], False),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libnamespacecmp.so.1.debug", ["package=libnamespacecmp", "dbg"], False),
    ]
    bsd_compress(name = name + "_manual", src = "libnamespacecmp.3",
        output = name + "/libnamespacecmp.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
        redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/libnamespacecmp.3.gz",
        select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libnamespacecmp-man"], "//conditions:default": ["package=libnamespacecmp-dev"]}), True))
    files.append(("namespacecmp.fidl", "/usr/share/fidl/namespacecmp.fidl", ["package=libnamespacecmp-dev"], False))
    files += [("//contrib/fuchsia:" + n, "/usr/share/licenses/libnamespacecmp/fuchsia/" + n, ["package=libnamespacecmp"], False) for n in ["LICENSE", "PATENTS"]]
    entries = []
    for source, destination, tags, is_manual in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(manual = is_manual, name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libnamespacecmp.so", target = "libnamespacecmp.so.1",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=libnamespacecmp", "dev"])
    for alias in MANUAL_ALIASES:
        target = name + "_manual_" + alias
        bsd_install_link(manual = True, name = target, destination = "/usr/share/man/man3/" + alias + ".3.gz",
            target = "/usr/share/man/man3/libnamespacecmp.3.gz", kind = "hardlink",
            owner = "root", group = "wheel", mode = "0444",
            install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libnamespacecmp-man"], "//conditions:default": ["package=libnamespacecmp-dev"]}))
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
