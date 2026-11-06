# SPDX-License-Identifier: BSD-2-Clause
load(":installation_data.bzl", "MANUALS", "MANUAL_LINKS")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

def _manpath(name):
    return "/usr/share/man/man" + name.rsplit(".", 1)[1] + "/" + name + ".gz"

def math_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":m_shared",
        binary_name = name + "/libm.so.5", debug_name = name + "/libm.so.5.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libm.so.5",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libm.a", ["package=clibs", "dev"], False),
        (":" + name + "_stripped", "/lib/libm.so.5", ["package=clibs"], False),
        (":" + name + "_symbols", "/usr/lib/debug/lib/libm.so.5.debug", ["package=clibs", "dbg"], False),
    ]
    # Current library implementation supports amd64 only.
    for source, header in [("x86/fenv.h", "fenv.h"), ("src/math.h", "math.h")]:
        files.append((source, "/usr/include/" + header, ["package=clibs", "dev"], False))
    for manual in MANUALS:
        target = name + "_manual_" + manual
        bsd_compress(name = target, src = "man/" + manual,
            output = name + "/" + manual + ".gz", arguments = ["-cn"],
            compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect",
            runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=clibs-man"],
            "//conditions:default": ["package=clibs-dev"]})
        files.append((":" + target, _manpath(manual), tags, True))
    entries = []
    for source, destination, tags, is_manual in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(manual = is_manual, name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    for original, alias in MANUAL_LINKS:
        target = name + "_alias_" + alias
        bsd_install_link(manual = True, name = target, destination = _manpath(alias), target = _manpath(original),
            kind = "hardlink", owner = "root", group = "wheel", mode = "0444",
            install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=clibs-man"],
                "//conditions:default": ["package=clibs-dev"]}))
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libm.so", target = "../../lib/libm.so.5",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=clibs", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
