# SPDX-License-Identifier: BSD-2-Clause
"""Native amd64 GENERIC built-in kernel objects and CTF."""
load("@rules_cc//cc:defs.bzl", "cc_library")
load("//tools/build/bazel:kernel_amd64.bzl", "AMD64_KERNEL_FLAGS", "AMD64_KERNEL_HEADER_DEPS")
load("//tools/build/bazel:bsd_ctf.bzl", "bsd_ctf_library")
def amd64_generic_kernel_objects(name, srcs, deps = [], copts = []):
    cc_library(name = name + "_objects", srcs = srcs,
        deps = AMD64_KERNEL_HEADER_DEPS + deps + ["//sys/kern:generic_offset_header", "//sys/kern:vnode_headers"],
        copts = [flag for flag in AMD64_KERNEL_FLAGS if flag != "-fcommon"] + ["-fno-common"] + copts,
        local_defines = ["_KERNEL", "HAVE_KERNEL_OPTION_HEADERS", "__printf__=__freebsd_kprintf__"],
        target_compatible_with = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"])
    bsd_ctf_library(name = name + "_ctf", library = ":" + name + "_objects",
        converter = "//cddl/usr.bin/ctfconvert:ctfconvert",
        runtime = ["//cddl/lib/libspl:spl_shared", "//lib/libdwarf:dwarf_shared", "//lib/libelf:elf_shared", "//lib/libz:z_shared",
            "@bsd_sdk//toolchain:sysroot/lib/libc.so.7", "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7"],
        ctf_label_setting = "//tools/build/bazel/config:kernel_ctf_label", preserve_debug = True)
    native.filegroup(name = name + "_object_files", srcs = [":" + name + "_ctf"], output_group = "regular_objects", visibility = ["//visibility:public"])
