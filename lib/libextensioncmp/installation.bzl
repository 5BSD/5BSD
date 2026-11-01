# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

MANUAL_ALIASES = ['extensioncmp_session_open', 'extensioncmp_session_create', 'extensioncmp_session_close', 'extensioncmp_load', 'extensioncmp_stat', 'extensioncmp_list', 'extensioncmp_reload', 'extensioncmp_manage', 'extensioncmp_info', 'extensioncmp_session_open_status', 'extensioncmp_session_create_status', 'extensioncmp_session_read_only', 'extensioncmp_decision', 'extensioncmp_session_open_rootload', 'extensioncmp_session_create_rootload', 'extensioncmp_root_load', 'extensioncmp_root_unload', 'service_ensure_extension', 'service_extension_stat', 'service_extension_list']

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":extensioncmp_shared",
        binary_name = name + "/libextensioncmp.so.1", debug_name = name + "/libextensioncmp.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libextensioncmp.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        ("extensioncmp.h", "/usr/include/extensioncmp.h", ["package=libextensioncmp", "dev"]),

        (":static_archive", "/usr/lib/libextensioncmp.a", ["package=libextensioncmp", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libextensioncmp.so.1", ["package=libextensioncmp"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libextensioncmp.so.1.debug", ["package=libextensioncmp", "dbg"]),
    ]
    bsd_compress(name = name + "_manual", src = "libextensioncmp.3",
        output = name + "/libextensioncmp.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
        redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/libextensioncmp.3.gz",
        select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libextensioncmp-man"], "//conditions:default": ["package=libextensioncmp-dev"]})))
    files.append(("extensioncmp.fidl", "/usr/share/fidl/extensioncmp.fidl", ["package=libextensioncmp-dev"]))
    files += [("//contrib/fuchsia:" + n, "/usr/share/licenses/libextensioncmp/fuchsia/" + n, ["package=libextensioncmp"]) for n in ["LICENSE", "PATENTS"]]
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libextensioncmp.so", target = "libextensioncmp.so.1",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=libextensioncmp", "dev"])
    for alias in MANUAL_ALIASES:
        target = name + "_manual_" + alias
        bsd_install_link(name = target, destination = "/usr/share/man/man3/" + alias + ".3.gz",
            target = "/usr/share/man/man3/libextensioncmp.3.gz", kind = "hardlink",
            owner = "root", group = "wheel", mode = "0444",
            install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libextensioncmp-man"], "//conditions:default": ["package=libextensioncmp-dev"]}))
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
