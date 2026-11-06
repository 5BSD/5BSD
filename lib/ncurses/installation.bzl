# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")
load("//tools/build/bazel:bsd_link_script.bzl", "bsd_link_script")
load("//tools/build/bazel:bsd_awk_output.bzl", "bsd_awk_output")
load("//lib/ncurses/tinfo:abi.bzl", "LIBRARY_ABIS")

def library_installation(name, library, headers, manuals, aliases):
    core = library == "ncurses"
    stem = "lib" + library + "w"
    soname = stem + ".so." + str(LIBRARY_ABIS[library + "w"])
    libdir = "/lib/" if core else "/usr/lib/"
    bsd_debug_split(name = name + "_debug", src = ":" + library + "_shared",
        binary_name = name + "/" + soname, debug_name = name + "/" + soname + ".debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/" + soname,
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    dev = ["package=ncurses", "dev"]
    files = [
        (":static_archive", "/usr/lib/" + stem + ("_real.a" if core else ".a"), dev),
        (":" + name + "_stripped", libdir + soname, ["package=ncurses", "lib"]),
        (":" + name + "_symbols", "/usr/lib/debug" + libdir + soname + ".debug", ["package=ncurses", "dbg"]),
    ] + [(source, "/usr/include/" + header, dev) for header, source in headers.items()]
    links = []
    if core:
        bsd_link_script(name = name + "_static_script", template = "libncursesw.aldscript",
            output = name + "/libncursesw.a", substitutions = {"@@LIB@@": "ncursesw", "@@STATICLIB_SUFFIX@@": "_real"})
        bsd_link_script(name = name + "_shared_script", template = "libncursesw.ldscript",
            output = name + "/libncursesw.so", substitutions = {"@@SHLIB@@": libdir + soname})
        files += [(":" + name + "_static_script", "/usr/lib/libncursesw.a", dev),
                  (":" + name + "_shared_script", "/usr/lib/libncursesw.so", dev)]
    else:
        links.append(("/usr/lib/" + stem + ".so", soname))
    for alias in (["cursesw", "ncurses", "curses"] if core else [library]):
        for suffix in [".a", ".so"]:
            links.append(("/usr/lib/lib" + alias + suffix, stem + suffix))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    for destination, link in links:
        target = name + "_link_" + destination.replace("/", "_")
        bsd_install_link(name = target, destination = destination, target = link,
            kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = dev)
        entries.append(":" + target)
    tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=ncurses-man"], "//conditions:default": ["package=ncurses-dev"]})
    for manual in manuals:
        target = name + "_man_" + manual.replace(".", "_")
        bsd_awk_output(name = target + "_configured",
            script = "//lib/ncurses/tinfo:configure-header.awk",
            srcs = ["//lib/ncurses/tinfo:header-policy.conf", "//contrib/ncurses:dist.mk", "//contrib/ncurses:man/" + manual + "x"],
            variables = {"substitution_names": "TERMINFO,DATADIR,NCURSES_OSPEED,NCURSES_MAJOR,NCURSES_MINOR,NCURSES_PATCH,TPUT,TSET,RESET,CLEAR,TABS,TIC,TOE,INFOCMP,CAPTOINFO,INFOTOCAP"},
            output = name + "/" + manual,
            awk = "@bsd_sdk//toolchain:awk", redirect = "@bsd_sdk//toolchain:stdout_redirect",
            runtime = ["@bsd_sdk//toolchain:awk_runtime"])
        bsd_compress(name = target, src = ":" + target + "_configured", output = name + "/" + manual + ".gz",
            arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect",
            runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        bsd_install_file(manual = True, name = target + "_file", src = ":" + target, destination = "/usr/share/man/man3/" + manual + ".gz",
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target + "_file")
    for manual, alias in aliases:
        target = name + "_alias_" + alias.replace(".", "_")
        bsd_install_link(manual = True, name = target, destination = "/usr/share/man/man3/" + alias + ".gz", target = "/usr/share/man/man3/" + manual + ".gz",
            kind = "hardlink", owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
