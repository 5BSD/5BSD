# SPDX-License-Identifier: BSD-2-Clause
"""Native amd64 GENERIC built-in kernel objects and CTF."""
load("@rules_cc//cc:defs.bzl", "cc_library")
load("//tools/build/bazel:kernel_amd64.bzl", "AMD64_KERNEL_FLAGS", "AMD64_KERNEL_WARNING_FLAGS", "AMD64_KERNEL_DEBUG_FLAGS", "AMD64_KERNEL_HEADER_DEPS")
load("//tools/build/bazel:bsd_ctf.bzl", "bsd_ctf_library")
def amd64_generic_kernel_objects(name, srcs, deps = [], copts = [], warning_flags = None, stack_protector = True, convert_ctf = True, early_deps = [], pre_copts = []):
    """Compile built-ins; early dependencies/flags preserve compatibility overlay order."""
    flags = [flag for flag in AMD64_KERNEL_FLAGS if flag != "-fcommon" and
             (stack_protector or flag != "-fstack-protector-strong")]
    warnings = AMD64_KERNEL_WARNING_FLAGS if warning_flags == None else warning_flags
    cc_library(name = name + "_objects", srcs = srcs,
        deps = early_deps + AMD64_KERNEL_HEADER_DEPS + deps + ["//sys/kern:generic_offset_header", "//sys/kern:vnode_headers"],
        copts = pre_copts + flags + ["-fno-common"] + warnings + AMD64_KERNEL_DEBUG_FLAGS + copts,
        local_defines = ["_KERNEL", "HAVE_KERNEL_OPTION_HEADERS", "__printf__=__freebsd_kprintf__"],
        target_compatible_with = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"])
    bsd_ctf_library(name = name + "_ctf", library = ":" + name + "_objects",
        converter = "//cddl/usr.bin/ctfconvert:ctfconvert",
        runtime = ["//cddl/lib/libspl:spl_shared", "//lib/libdwarf:dwarf_shared", "//lib/libelf:elf_shared", "//lib/libz:z_shared",
            "@bsd_sdk//toolchain:sysroot/lib/libc.so.7", "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7"],
        ctf_label_setting = "//tools/build/bazel/config:kernel_ctf_label", preserve_debug = True,
        enabled = select({"//tools/build/bazel/config:kernel_ctf_enabled": True, "//conditions:default": False}) if convert_ctf else False)
    native.filegroup(name = name + "_object_files", srcs = [":" + name + "_ctf"], output_group = "regular_objects", visibility = ["//visibility:public"])
