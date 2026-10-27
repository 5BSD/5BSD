# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")
load(":abi.bzl", "LIBRARY_ABIS")
load(":manuals.bzl", "DEVELOPMENT_MANUALS", "RUNTIME_MANUALS", "MANUAL_LINKS")

def library_manual_installation(name):
    """Library, headers and manuals; pkg-config is a separate required component."""
    soname = "libtinfow.so." + str(LIBRARY_ABIS["tinfow"])
    bsd_debug_split(name = name + "_debug", src = ":tinfo_shared",
        binary_name = name + "/" + soname, debug_name = name + "/" + soname + ".debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/" + soname,
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libtinfow.a", ["package=ncurses", "dev"]),
        (":" + name + "_stripped", "/lib/" + soname, ["package=ncurses", "lib"]),
        (":" + name + "_symbols", "/usr/lib/debug/lib/" + soname + ".debug", ["package=ncurses", "dbg"]),
    ] + [(":" + header + "_header", "/usr/include/" + header + ".h", ["package=ncurses", "dev"])
         for header in ["curses", "ncurses_dll", "term", "termcap", "unctrl"]]
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    links = [("/usr/lib/libtinfow.so", "../../lib/" + soname), ("/usr/include/ncurses.h", "curses.h")]
    links += [("/usr/lib/lib" + alias + suffix, "libtinfow" + suffix)
              for suffix in [".a", ".so"] for alias in ["termcapw", "termlibw", "termcap", "termlib", "tinfo"]]
    for destination, link in links:
        target = name + "_link_" + destination.replace("/", "_")
        bsd_install_link(name = target, destination = destination, target = link,
            kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=ncurses", "dev"])
        entries.append(":" + target)
    for manual in DEVELOPMENT_MANUALS + RUNTIME_MANUALS:
        target = name + "_man_" + manual.replace(".", "_")
        tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=ncurses-man"],
            "//conditions:default": ["package=ncurses-dev"] if manual in DEVELOPMENT_MANUALS else ["package=ncurses"]})
        bsd_compress(name = target, src = ":manual_" + manual.replace(".", "_"), output = name + "/" + manual + ".gz",
            arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect",
            runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        bsd_install_file(name = target + "_file", src = ":" + target, destination = "/usr/share/man/man" + manual.rsplit(".", 1)[1] + "/" + manual + ".gz",
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target + "_file")
    for manual, alias in MANUAL_LINKS:
        target = name + "_alias_" + alias.replace(".", "_")
        tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=ncurses-man"],
            "//conditions:default": ["package=ncurses-dev"] if manual in DEVELOPMENT_MANUALS else ["package=ncurses"]})
        bsd_install_link(name = target, destination = "/usr/share/man/man" + alias.rsplit(".", 1)[1] + "/" + alias + ".gz",
            target = "/usr/share/man/man" + manual.rsplit(".", 1)[1] + "/" + manual + ".gz",
            kind = "hardlink", owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])

def pkgconfig_installation(name):
    """Install wide-character metadata and the maintained compatibility aliases."""
    entries = []
    for module in LIBRARY_ABIS:
        target = name + "_" + module
        bsd_install_file(name = target, src = ":pkgconfig_" + module,
            destination = "/usr/libdata/pkgconfig/" + module + ".pc",
            owner = "root", group = "wheel", mode = "0444",
            install_tags = ["package=ncurses", "dev"])
        bsd_install_link(name = target + "_alias",
            destination = "/usr/libdata/pkgconfig/" + module[:-1] + ".pc",
            target = module + ".pc", kind = "symlink",
            owner = "root", group = "wheel", mode = "0755",
            install_tags = ["package=ncurses", "dev"])
        entries += [":" + target, ":" + target + "_alias"]
    bsd_install_manifest(name = name, entries = entries, visibility = ["//lib/ncurses:__pkg__", "//packages/ncurses:__pkg__"])
