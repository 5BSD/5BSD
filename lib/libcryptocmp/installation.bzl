# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

MANUAL_ALIASES = ['cryptocmp_open', 'cryptocmp_close', 'cryptocmp_generate', 'cryptocmp_generate_key', 'cryptocmp_digest', 'cryptocmp_random', 'cryptocmp_named_create', 'cryptocmp_named_lease', 'cryptocmp_named_rotate', 'cryptocmp_named_delete', 'cryptocmp_named_stat', 'cryptocmp_named_list', 'cryptocmp_client_create']

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":cryptocmp_shared",
        binary_name = name + "/libcryptocmp.so.1", debug_name = name + "/libcryptocmp.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libcryptocmp.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        ("cryptocmp.h", "/usr/include/cryptocmp.h", ["package=libcryptocmp", "dev"]),

        ("cryptocmp_protocol.h", "/usr/include/cryptocmp_protocol.h", ["package=libcryptocmp", "dev"]),
        (":static_archive", "/usr/lib/libcryptocmp.a", ["package=libcryptocmp", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libcryptocmp.so.1", ["package=libcryptocmp"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libcryptocmp.so.1.debug", ["package=libcryptocmp", "dbg"]),
    ]
    bsd_compress(name = name + "_manual", src = "libcryptocmp.3",
        output = name + "/libcryptocmp.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
        redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/libcryptocmp.3.gz",
        select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libcryptocmp-man"], "//conditions:default": ["package=libcryptocmp-dev"]})))
    files.append(("cryptocmp.fidl", "/usr/share/fidl/cryptocmp.fidl", ["package=libcryptocmp-dev"]))
    files += [("//contrib/fuchsia:" + n, "/usr/share/licenses/libcryptocmp/fuchsia/" + n, ["package=libcryptocmp"]) for n in ["LICENSE", "PATENTS"]]
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libcryptocmp.so", target = "libcryptocmp.so.1",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=libcryptocmp", "dev"])
    for alias in MANUAL_ALIASES:
        target = name + "_manual_" + alias
        bsd_install_link(name = target, destination = "/usr/share/man/man3/" + alias + ".3.gz",
            target = "/usr/share/man/man3/libcryptocmp.3.gz", kind = "hardlink",
            owner = "root", group = "wheel", mode = "0444",
            install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libcryptocmp-man"], "//conditions:default": ["package=libcryptocmp-dev"]}))
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
