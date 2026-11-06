# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

_HEADERS = {'histedit.h': '//contrib/libedit:histedit.h', 'filecomplete.h': '//contrib/libedit:filecomplete.h', 'edit/readline/readline.h': '//contrib/libedit:readline/readline.h', 'edit/readline/history.h': '//lib/libedit/readline:history.h', 'edit/readline/tilde.h': '//lib/libedit/readline:tilde.h'}
_MANUAL_ALIASES = ['el_deletestr.3', 'el_end.3', 'el_get.3', 'el_getc.3', 'el_gets.3', 'el_init.3', 'el_init_fd.3', 'el_insertstr.3', 'el_line.3', 'el_parse.3', 'el_push.3', 'el_reset.3', 'el_resize.3', 'el_set.3', 'el_source.3', 'history.3', 'history_end.3', 'history_init.3', 'tok_end.3', 'tok_init.3', 'tok_line.3', 'tok_reset.3', 'tok_str.3', 'el_wdeletestr.3', 'el_wget.3', 'el_wgetc.3', 'el_wgets.3', 'el_winsertstr.3', 'el_wline.3', 'el_wparse.3', 'el_wpush.3', 'el_wset.3', 'history_w.3', 'history_wend.3', 'history_winit.3', 'tok_wend.3', 'tok_winit.3', 'tok_wline.3', 'tok_wreset.3', 'tok_wstr.3']

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":edit_shared",
        binary_name = name + "/libedit.so.8", debug_name = name + "/libedit.so.8.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libedit.so.8",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libedit.a", ["package=runtime", "dev"]),
        (":" + name + "_stripped", "/lib/libedit.so.8", ["package=runtime"]),
        (":" + name + "_symbols", "/usr/lib/debug/lib/libedit.so.8.debug", ["package=runtime", "dbg"]),
    ]
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libedit.so", target = "../../lib/libedit.so.8",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=runtime", "dev"])
    entries.append(":" + name + "_link")
    for header, source in _HEADERS.items():
        target = name + "_header_" + header.replace("/", "_").replace(".", "_")
        bsd_install_file(name = target, src = source,
            destination = "/usr/include/" + header, owner = "root", group = "wheel",
            mode = "0444", install_tags = ["package=runtime", "dev"])
        entries.append(":" + target)
    tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=runtime-man"], "//conditions:default": ["package=runtime-dev"]})
    bsd_compress(name = name + "_manual", src = "//contrib/libedit:editline.3", output = name + "/editline.3.gz",
        arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect",
        runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    bsd_install_file(manual = True, name = name + "_man", src = ":" + name + "_manual", destination = "/usr/share/man/man3/editline.3.gz",
        owner = "root", group = "wheel", mode = "0444", install_tags = tags)
    entries.append(":" + name + "_man")
    for alias in _MANUAL_ALIASES:
        target = name + "_man_" + alias.replace(".", "_")
        bsd_install_link(manual = True, name = target, destination = "/usr/share/man/man3/" + alias + ".gz",
            target = "/usr/share/man/man3/editline.3.gz", kind = "hardlink",
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    for manual, section in [("editrc.5", "5"), ("editline.7", "7")]:
        target = name + "_" + manual.replace(".", "_")
        tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=runtime-man"], "//conditions:default": ["package=runtime"]})
        bsd_compress(name = target, src = "//contrib/libedit:" + manual, output = name + "/" + manual + ".gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        bsd_install_file(manual = True, name = target + "_file", src = ":" + target, destination = "/usr/share/man/man" + section + "/" + manual + ".gz", owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target + "_file")
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
