# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")



def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":stdthreads_shared",
        binary_name = name + "/libstdthreads.so.0", debug_name = name + "/libstdthreads.so.0.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libstdthreads.so.0",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libstdthreads.a", ["package=runtime", "dev"], False),
        (":" + name + "_stripped", "/usr/lib/libstdthreads.so.0", ["package=runtime"], False),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libstdthreads.so.0.debug", ["package=runtime", "dbg"], False),
    ]
    files.append(("threads.h", "/usr/include/threads.h", ["package=runtime", "dev"], False))
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=runtime-man"], "//conditions:default": ["package=runtime-dev"]})
    bsd_compress(name = name + "_manual", src = "thrd_create.3", output = name + "/thrd_create.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/thrd_create.3.gz", man_tags, True))
    entries = []
    for source, destination, tags, is_manual in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(manual = is_manual, name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libstdthreads.so", target = "libstdthreads.so.0",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=runtime", "dev"])
    for manual in ['call_once', 'cnd_broadcast', 'cnd_destroy', 'cnd_init', 'cnd_signal', 'cnd_timedwait', 'cnd_wait', 'mtx_destroy', 'mtx_init', 'mtx_lock', 'mtx_timedlock', 'mtx_trylock', 'mtx_unlock', 'thrd_current', 'thrd_detach', 'thrd_equal', 'thrd_exit', 'thrd_join', 'thrd_sleep', 'thrd_yield', 'tss_create', 'tss_delete', 'tss_get', 'tss_set']:
        alias = name + "_manual_" + manual
        bsd_install_link(manual = True, name = alias, destination = "/usr/share/man/man3/" + manual + ".3.gz",
            target = "/usr/share/man/man3/thrd_create.3.gz", kind = "hardlink", owner = "root", group = "wheel", mode = "0444", install_tags = man_tags)
        entries.append(":" + alias)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
