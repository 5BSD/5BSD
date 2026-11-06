# SPDX-License-Identifier: BSD-2-Clause
"""Source-owned sendmail programs and original package installation."""
load("@rules_cc//cc:defs.bzl", "cc_binary")
load("//tools/build/bazel:bsd_nis.bzl", "nis_runtime_deps", "nis_runtime_linkopts")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")
load("//tools/build/bazel:bsd_install.bzl", "bsd_compress", "bsd_install_file", "bsd_install_manifest")

def sendmail_program(name, srcs, deps, shared = [], defines = [], bindir = "/usr/sbin", group = "wheel", mode = "0555", package = "utilities", manuals = [], manual_aliases = []):
    cc_binary(name = name, srcs = srcs, deps = deps + nis_runtime_deps(),
        dynamic_deps = shared, local_defines = defines,
        copts = ["-fPIE", "-std=gnu17", "-Wno-deprecated-non-prototype"],
        linkopts = ["-pie"] + nis_runtime_linkopts(), linkstatic = True,
        target_compatible_with = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"] + select({
            "//tools/build/bazel/config:sendmail_enabled": [], "//conditions:default": ["@platforms//:incompatible"]}),
        visibility = ["//visibility:public"])
    utility_installation(name = "install_manifest", program = name, manual = "//contrib/sendmail:" + ("src/" if name == "sendmail" else name + "/") + name + ".8",
        man_section = "8", package = package, bindir = bindir, binary_group = group, binary_mode = mode, manual_aliases = manual_aliases)
    entries = []
    for manual in manuals:
        target = "manual_" + manual.replace(".", "_")
        bsd_compress(name = target, src = "//contrib/sendmail:src/" + manual, output = manual + ".gz",
            arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
            redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        bsd_install_file(manual = True, name = target + "_file", src = ":" + target, destination = "/usr/share/man/man" + manual.rsplit(".", 1)[1] + "/" + manual + ".gz",
            owner = "root", group = "wheel", mode = "0444", install_tags = select({
                "//tools/build/bazel/config:split_manpages_enabled": ["package=" + package + "-man"], "//conditions:default": ["package=" + package]}))
        entries.append(":" + target + "_file")
    bsd_install_manifest(name = "extra_manuals", entries = entries)
    directories = {}
    current = "/usr/lib/debug"
    for component in bindir.removeprefix("/").split("/"):
        current += "/" + component
        directories[current] = json.encode({"owner": "root", "group": "wheel", "mode": "0755", "tags": ["package=" + package, "dbg"]})
    bsd_install_archive(name = "install_archive", manifests = [":install_manifest", ":extra_manuals"], directories = directories,
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr", "//etc/mtree:BSD.debug.dist": "/usr/lib"},
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"], visibility = ["//visibility:public"])
