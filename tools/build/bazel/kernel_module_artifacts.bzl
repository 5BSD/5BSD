# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_kernel_module.bzl", "bsd_module_link", "bsd_module_exports")
load("//tools/build/bazel:bsd_ctf.bzl", "bsd_ctf_merge")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest")


_KERNEL_CTF = select({"//tools/build/bazel/config:kernel_ctf_enabled": True, "//conditions:default": False})

def kernel_module_artifacts(module, objects, emulation, script = None, linkopts = [], shared = False,
                            prefix = "", exports = [], export_all = False, package = "kernel",
                            linker_inputs = ["@bsd_sdk//toolchain:link_inputs"]):
    """Preserve the maintained link/CTF/export/debug/install stage ordering."""
    if export_all and exports:
        fail("export_all and an explicit export list are mutually exclusive")
    bsd_module_link(name = prefix + "generic_link", objects = objects,
        script = script, emulation = emulation, linkopts = linkopts, output = prefix + "generic/%s.linked" % module,
        linker = "@bsd_sdk//toolchain:bin/ld.lld", linker_inputs = linker_inputs)
    bsd_ctf_merge(name = prefix + "generic_ctf", linked = ":" + prefix + "generic_link", objects = objects,
        output = prefix + ("generic/%s.kld" if export_all and shared else "generic/%s.ko.full" if export_all else "generic/%s.ctf") % module, enabled = _KERNEL_CTF,
        ctf_label_setting = "//tools/build/bazel/config:kernel_ctf_label", preserve_debug = True,
        merger = "//cddl/usr.bin/ctfmerge:ctfmerge", copy_runner = "//tools/build/bazel:dtrace_copy_runner",
        runtime = ["//lib/libelf:elf_shared", "//lib/libz:z_shared", "//cddl/lib/libspl:spl_shared",
            "@bsd_sdk//toolchain:sysroot/lib/libc.so.7", "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7", "@bsd_sdk//toolchain:sysroot/lib/libthr.so.3"])
    full_name = "generic_localized" if shared else "generic_full"
    if export_all:
        native.alias(name = prefix + full_name, actual = ":" + prefix + "generic_ctf", visibility = ["//visibility:public"])
    else:
        bsd_module_exports(name = prefix + full_name, src = ":" + prefix + "generic_ctf", output = prefix + ("generic/%s.kld" if shared else "generic/%s.ko.full") % module,
            exports = exports,
            nm = "@bsd_sdk//toolchain:bin/llvm-nm", objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy",
            tool_inputs = ["@bsd_sdk//toolchain:llvm-nm_runtime", "@bsd_sdk//toolchain:objcopy_inputs"],
            redirect = "@bsd_sdk//toolchain:stdout_redirect",
            libraries = ["//lib/msun:m_shared", "@bsd_sdk//toolchain:sysroot/lib/libc.so.7", "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7"],
            python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
            runtime = ["@bsd_sdk//toolchain:python_stdlib"], visibility = ["//visibility:public"])
    if shared:
        bsd_module_link(name = prefix + "generic_full", objects = [":" + prefix + full_name],
            emulation = emulation, shared = True, linkopts = linkopts,
            output = prefix + "generic/%s.ko.full" % module,
            linker = "@bsd_sdk//toolchain:bin/ld.lld", linker_inputs = linker_inputs,
            visibility = ["//visibility:public"])
    bsd_debug_split(name = prefix + "generic_module", src = ":" + prefix + "generic_full", binary_name = prefix + "generic/%s.ko" % module, debug_name = prefix + "generic/%s.ko.debug" % module,
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs",
        enabled = select({"//tools/build/bazel/config:kernel_debug_enabled": True, "//conditions:default": False}),
        visibility = ["//visibility:public"])
    native.filegroup(name = prefix + "generic_debug", srcs = [":" + prefix + "generic_module"], output_group = "debug_files", visibility = ["//visibility:public"])

    bsd_install_file(name = prefix + "install_module", src = ":" + prefix + "generic_module", destination = "/%s.ko" % module,
        destination_prefixes = ["//tools/build/bazel/config:kernel_directory"],
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=" + package])
    bsd_install_file(name = prefix + "install_debug", src = ":" + prefix + "generic_debug", destination = "/%s.ko.debug" % module,
        destination_prefixes = ["//tools/build/bazel/config:kernel_debug_directory", "//tools/build/bazel/config:kernel_directory"],
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=" + package, "dbg"])
    bsd_install_manifest(name = prefix + "install_manifest",
        entries = [":" + prefix + "install_module"] + select({
            "//tools/build/bazel/config:kernel_debug_enabled": [":" + prefix + "install_debug"],
            "//conditions:default": [],
        }), visibility = ["//visibility:public"])
