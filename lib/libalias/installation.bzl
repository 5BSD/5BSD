# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")

def alias_installation(library, shared, main = False):
    soname = "lib" + library + (".so.7" if main else ".so")
    bsd_debug_split(name = "debug", src = shared, binary_name = "debug/" + soname, debug_name = "debug/" + soname + ".debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = "stripped", src = ":debug", output = "stripped/" + soname,
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = "symbols", srcs = [":debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/lib" + library + ".a", ["package=libalias", "dev"], "0444"),
        (":stripped", "/lib/" + soname, ["package=libalias"], "0444"),
        (":symbols", "/usr/lib/debug/lib/" + soname + ".debug", ["package=libalias", "dbg"], "0444"),
    ]
    extra = []
    if main:
        files += [("//sys/netinet/libalias:alias.h", "/usr/include/alias.h", ["package=libalias", "dev"], "0444"),
                  ("libalias.conf", "/etc/libalias.conf", ["package=libalias", "config"], "0644")]
        bsd_compress(name = "manual", src = "//sys/netinet/libalias:libalias.3", output = "libalias.3.gz", arguments = ["-cn"],
            compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        files.append((":manual", "/usr/share/man/man3/libalias.3.gz", select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libalias-man"], "//conditions:default": ["package=libalias-dev"]}), "0444"))
        bsd_install_link(name = "library_link", destination = "/usr/lib/libalias.so", target = "../../lib/libalias.so.7", kind = "symlink",
            owner = "root", group = "wheel", mode = "0755", install_tags = ["package=libalias", "dev"])
        extra.append(":library_link")
    entries = []
    for source, destination, tags, mode in files:
        name = "file_" + destination.replace("/", "_")
        bsd_install_file(name = name, src = source, destination = destination, owner = "root", group = "wheel", mode = mode, install_tags = tags)
        entries.append(":" + name)
    bsd_install_manifest(name = "install_manifest", entries = entries + extra)
    bsd_install_archive(name = "install_archive", manifests = [":install_manifest"],
        directories = {"/usr/lib/debug/lib": '{"owner":"root","group":"wheel","mode":"0755","tags":["package=libalias","dbg"]}'} | ({"/etc": '{"owner":"root","group":"wheel","mode":"0755","tags":["package=utilities"]}'} if main else {}),
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr", "//etc/mtree:BSD.include.dist": "/usr/include", "//etc/mtree:BSD.debug.dist": "/usr/lib"},
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"], visibility = ["//lib/libalias:__pkg__"])
