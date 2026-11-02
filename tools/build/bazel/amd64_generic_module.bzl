# SPDX-License-Identifier: BSD-2-Clause
"""GENERIC amd64 module artifacts, with declared CTF and export processing."""

load(":kernel_module_artifacts.bzl", "kernel_module_artifacts")
load(":kernel_source_paths.bzl", "module_source_path_maps")
load("@rules_cc//cc:defs.bzl", "cc_library")
load("//tools/build/bazel:kernel_amd64.bzl", "AMD64_KERNEL_FLAGS", "AMD64_KERNEL_WARNING_FLAGS", "AMD64_KERNEL_DEBUG_FLAGS", "AMD64_KERNEL_HEADER_DEPS")
load("//tools/build/bazel:bsd_ctf.bzl", "bsd_ctf_library")

_KERNEL_CTF = select({
    "//tools/build/bazel/config:kernel_ctf_enabled": True,
    "//conditions:default": False,
})


def amd64_generic_module(module, objects, exports = [], export_all = False, package = "kernel", object_order = [], aliases = []):
    kernel_module_artifacts(module = module, objects = objects, exports = exports,
        export_all = export_all, package = package, object_order = object_order, aliases = aliases,
        script = "//sys/conf:ldscript.kmod.amd64", emulation = "elf_x86_64_fbsd")

def amd64_generic_module_objects(srcs, deps = [], name = "generic_module", copts = [], textual_hdrs = [], header_overrides = [], warning_flags = None, preinclude_headers = [], local_defines = [], additional_compiler_inputs = [], convert_ctf = True, kernel_flags = None, features = []):
    """Compile a source group; convert_ctf controls participation in the selected kernel CTF mode.

    Custom original assembly recipes may explicitly skip CTF conversion. The
    default preserves the selected kernel policy for ordinary source groups.
    kernel_flags may supply a source-owned replacement for the common vector;
    features forwards native cc_library toolchain feature requests unchanged.
    """
    if type(convert_ctf) != "bool":
        fail("convert_ctf must be a bool")
    flags = AMD64_KERNEL_FLAGS if kernel_flags == None else kernel_flags
    # Preserve forced compatibility headers before the ordinary opt_global.h input.
    textual_hdrs = preinclude_headers + textual_hdrs
    preinclude_flags = [flag for header in preinclude_headers for flag in ["-include", "$(execpath " + header + ")"]]
    cc_library(name = name + "_objects", srcs = srcs, textual_hdrs = textual_hdrs,
        # rules_cc permits execpath expansion in copts for these inputs.
        additional_compiler_inputs = textual_hdrs + additional_compiler_inputs,
        deps = header_overrides + AMD64_KERNEL_HEADER_DEPS + deps + ["//sys/kern:generic_offset_header", "//sys/kern:vnode_headers"],
        copts = preinclude_flags + [flag for flag in flags if flag != "-fcommon"] + ["-fno-common"] + (AMD64_KERNEL_WARNING_FLAGS if warning_flags == None else warning_flags) + AMD64_KERNEL_DEBUG_FLAGS +
            # Inline code in declared transitive headers also embeds __FILE__.
            # Use the same canonical source paths as the individual sources.
            ["-fmacro-prefix-map=sys/=/usr/src/sys/", "-fdebug-prefix-map=sys/=/usr/src/sys/"] +
            [mapping for source in srcs + textual_hdrs for mapping in module_source_path_maps(source)] + copts,
        local_defines = ["_KERNEL", "KLD_MODULE", "KLD_TIED", "HAVE_KERNEL_OPTION_HEADERS", "__printf__=__freebsd_kprintf__"] + local_defines,
        features = features,
        target_compatible_with = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"])
    bsd_ctf_library(name = name + "_ctf", library = ":" + name + "_objects",
        converter = "//cddl/usr.bin/ctfconvert:ctfconvert",
        runtime = ["//cddl/lib/libspl:spl_shared", "//lib/libdwarf:dwarf_shared", "//lib/libelf:elf_shared", "//lib/libz:z_shared",
            "@bsd_sdk//toolchain:sysroot/lib/libc.so.7", "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7"],
        ctf_label_setting = "//tools/build/bazel/config:kernel_ctf_label", preserve_debug = True,
        enabled = _KERNEL_CTF if convert_ctf else False)
    native.filegroup(name = name + "_object_files", srcs = [":" + name + "_ctf"], output_group = "regular_objects", visibility = ["//visibility:public"])
