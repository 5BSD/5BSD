# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

def module_installation(name, module, manuals = None, package = "pam", manual_sources = {}):
    bsd_debug_split(name = name + "_debug", src = ":" + module,
        binary_name = name + "/" + module + ".so.6", debug_name = name + "/" + module + ".so.6.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/" + module + ".so.6",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":" + name + "_stripped", "/usr/lib/" + module + ".so.6", ["package=" + package]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/" + module + ".so.6.debug", ["package=" + package, "dbg"]),
    ]
    selected_manuals = manuals if manuals != None else [module + ".8"]
    for manual in manual_sources:
        if manual not in selected_manuals:
            fail("manual source override has no matching installed manual: " + manual)
    for manual in selected_manuals:
        section = manual.rsplit(".", 1)[-1]
        if section not in ["1", "2", "3", "4", "5", "6", "7", "8", "9"] or "/" in manual:
            fail("PAM manual must be a local basename with a section suffix")
        target = name + "_manual_" + manual
        bsd_compress(name = target, src = manual_sources.get(manual, manual), output = name + "/" + manual + ".gz",
            arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
            redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        files.append((":" + target, "/usr/share/man/man" + section + "/" + manual + ".gz",
            select({"//tools/build/bazel/config:split_manpages_enabled": ["package=" + package + "-man"], "//conditions:default": ["package=" + package]})))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/" + module + ".so", target = module + ".so.6",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=" + package])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
