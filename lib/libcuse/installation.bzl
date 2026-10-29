# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")



def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":cuse_shared",
        binary_name = name + "/libcuse.so.1", debug_name = name + "/libcuse.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libcuse.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libcuse.a", ["package=libcuse", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libcuse.so.1", ["package=libcuse"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libcuse.so.1.debug", ["package=libcuse", "dbg"]),
    ]
    files.append(("cuse.h", "/usr/include/cuse.h", ["package=libcuse", "dev"]))
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libcuse-man"], "//conditions:default": ["package=libcuse-dev"]})
    bsd_compress(name = name + "_manual", src = "cuse.3", output = name + "/cuse.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/cuse.3.gz", man_tags))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libcuse.so", target = "libcuse.so.1",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=libcuse", "dev"])
    for manual in ['cuse_alloc_unit_number', 'cuse_alloc_unit_number_by_id', 'cuse_copy_in', 'cuse_copy_out', 'cuse_dev_create', 'cuse_dev_destroy', 'cuse_dev_get_current', 'cuse_dev_get_per_file_handle', 'cuse_dev_get_priv0', 'cuse_dev_get_priv1', 'cuse_dev_set_per_file_handle', 'cuse_dev_set_priv0', 'cuse_dev_set_priv1', 'cuse_free_unit_number', 'cuse_free_unit_number_by_id', 'cuse_got_peer_signal', 'cuse_init', 'cuse_poll_wakeup', 'cuse_set_local', 'cuse_get_local', 'cuse_uninit', 'cuse_vmalloc', 'cuse_is_vmalloc_addr', 'cuse_vmfree', 'cuse_vmoffset', 'cuse_wait_and_process']:
        alias = name + "_manual_" + manual
        bsd_install_link(name = alias, destination = "/usr/share/man/man3/" + manual + ".3.gz",
            target = "/usr/share/man/man3/cuse.3.gz", kind = "hardlink", owner = "root", group = "wheel", mode = "0444", install_tags = man_tags)
        entries.append(":" + alias)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
