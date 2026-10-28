# SPDX-License-Identifier: BSD-2-Clause
"""GENERIC amd64 module artifacts, with declared CTF and export processing."""
load("//tools/build/bazel:bsd_kernel_module.bzl", "bsd_module_link", "bsd_module_exports")
load("//tools/build/bazel:bsd_ctf.bzl", "bsd_ctf_merge")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest")

load("@rules_cc//cc:defs.bzl", "cc_library")
load("//tools/build/bazel:kernel_amd64.bzl", "AMD64_KERNEL_FLAGS", "AMD64_KERNEL_HEADER_DEPS")
load("//tools/build/bazel:bsd_ctf.bzl", "bsd_ctf_library")

def amd64_generic_module(module, objects, exports = [], export_all = False):
    """Build runtime/debug artifacts and kernel installation metadata.

    An empty export list implements kmod.mk EXPORT_SYMS=NO.
    export_all implements EXPORT_SYMS=YES without symbol localization.
    This macro currently supports GENERIC tied modules and the amd64 relocatable ABI.
    """
    if export_all and exports:
        fail("export_all and an explicit export list are mutually exclusive")
    bsd_module_link(name = "generic_link", objects = objects,
        script = "//sys/conf:ldscript.kmod.amd64", emulation = "elf_x86_64_fbsd", output = "generic/%s.linked" % module,
        linker = "@bsd_sdk//toolchain:bin/ld.lld", linker_inputs = ["@bsd_sdk//toolchain:link_inputs"])
    bsd_ctf_merge(name = "generic_ctf", linked = ":generic_link", objects = objects,
        output = ("generic/%s.ko.full" if export_all else "generic/%s.ctf") % module, ctf_label_setting = "//tools/build/bazel/config:kernel_ctf_label", preserve_debug = True,
        merger = "//cddl/usr.bin/ctfmerge:ctfmerge", copy_runner = "//tools/build/bazel:dtrace_copy_runner",
        runtime = ["//lib/libelf:elf_shared", "//lib/libz:z_shared", "//cddl/lib/libspl:spl_shared",
            "@bsd_sdk//toolchain:sysroot/lib/libc.so.7", "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7", "@bsd_sdk//toolchain:sysroot/lib/libthr.so.3"])
    if export_all:
        native.alias(name = "generic_full", actual = ":generic_ctf", visibility = ["//visibility:public"])
    else:
        bsd_module_exports(name = "generic_full", src = ":generic_ctf", output = "generic/%s.ko.full" % module,
            exports = exports,
            nm = "@bsd_sdk//toolchain:bin/llvm-nm", objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy",
            tool_inputs = ["@bsd_sdk//toolchain:llvm-nm_runtime", "@bsd_sdk//toolchain:objcopy_inputs"],
            redirect = "@bsd_sdk//toolchain:stdout_redirect",
            libraries = ["//lib/msun:m_shared", "@bsd_sdk//toolchain:sysroot/lib/libc.so.7", "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7"],
            python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
            runtime = ["@bsd_sdk//toolchain:python_stdlib"], visibility = ["//visibility:public"])
    bsd_debug_split(name = "generic_module", src = ":generic_full", binary_name = "generic/%s.ko" % module, debug_name = "generic/%s.ko.debug" % module,
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs", visibility = ["//visibility:public"])
    native.filegroup(name = "generic_debug", srcs = [":generic_module"], output_group = "debug_files", visibility = ["//visibility:public"])

    bsd_install_file(name = "install_module", src = ":generic_module", destination = "/%s.ko" % module,
        destination_prefixes = ["//tools/build/bazel/config:kernel_directory"],
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=kernel"])
    bsd_install_file(name = "install_debug", src = ":generic_debug", destination = "/%s.ko.debug" % module,
        destination_prefixes = ["//tools/build/bazel/config:kernel_debug_directory", "//tools/build/bazel/config:kernel_directory"],
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=kernel", "dbg"])
    bsd_install_manifest(name = "install_manifest", entries = [":install_module", ":install_debug"], visibility = ["//visibility:public"])

def amd64_generic_module_objects(srcs, deps = []):
    """Compile explicitly enumerated sources against the GENERIC headers."""
    cc_library(name = "generic_module_objects", srcs = srcs,
        deps = AMD64_KERNEL_HEADER_DEPS + deps + ["//sys/kern:generic_offset_header", "//sys/kern:vnode_headers"],
        copts = [flag for flag in AMD64_KERNEL_FLAGS if flag != "-fcommon"] + ["-fno-common"],
        local_defines = ["_KERNEL", "KLD_MODULE", "KLD_TIED", "HAVE_KERNEL_OPTION_HEADERS", "__printf__=__freebsd_kprintf__"],
        target_compatible_with = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"])
    bsd_ctf_library(name = "generic_module_ctf", library = ":generic_module_objects",
        converter = "//cddl/usr.bin/ctfconvert:ctfconvert",
        runtime = ["//cddl/lib/libspl:spl_shared", "//lib/libdwarf:dwarf_shared", "//lib/libelf:elf_shared", "//lib/libz:z_shared",
            "@bsd_sdk//toolchain:sysroot/lib/libc.so.7", "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7"],
        ctf_label_setting = "//tools/build/bazel/config:kernel_ctf_label", preserve_debug = True)
    native.filegroup(name = "generic_module_object_files", srcs = [":generic_module_ctf"], output_group = "regular_objects", visibility = ["//visibility:public"])
