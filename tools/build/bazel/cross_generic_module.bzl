# SPDX-License-Identifier: BSD-2-Clause
"""Explicit ARM64/RISC-V GENERIC tied module consumers of the kernel ABI."""
load("@rules_cc//cc:defs.bzl", "cc_library")
load(":kernel_common.bzl", "KERNEL_WARNING_FLAGS", "KERNEL_DEBUG_FLAGS")
load(":kernel_module_artifacts.bzl", "kernel_module_artifacts")
load(":bsd_ctf.bzl", "bsd_ctf_library")

_ARCH = {
    "arm64": struct(cpu = "aarch64", emulation = "aarch64elf",
        copts = ["-mgeneral-regs-only", "-ffixed-x18", "-mbranch-protection=standard", "-mno-outline-atomics",
            "-mstack-protector-guard=sysreg", "-mstack-protector-guard-reg=sp_el0", "-mstack-protector-guard-offset=0"],
        headers = ["//sys/arm/include:kernel_headers"],
        linkopts = ["--fix-cortex-a53-843419", "--no-relax", "-zbti-report=error"]),
    "riscv": struct(cpu = "riscv64", emulation = "elf64lriscv",
        copts = ["-march=rv64imafdch_zifencei_svinval", "-mabi=lp64", "-mcmodel=medium", "-mno-relax"],
        headers = [], linkopts = []),
}

def cross_generic_module_objects(arch, srcs, textual_hdrs = [], deps = [], name = "generic_module", copts = []):
    policy = _ARCH[arch]
    name = arch + "_" + name
    cc_library(name = name + "_objects", srcs = srcs, textual_hdrs = textual_hdrs,
        additional_compiler_inputs = textual_hdrs,
        deps = ["//sys/" + arch + "/conf:generic_global_headers", "//sys/" + arch + "/include:kernel_headers",
            "//sys/kern:" + arch + "_generic_offset_header", "//sys/kern:vnode_headers",
            "//sys/sys:kernel_headers", "//sys/bsm:kernel_headers"] + policy.headers + deps,
        copts = ["-fno-strict-aliasing", "-fno-common", "-include", "opt_global.h", "-fPIC",
            "-fno-omit-frame-pointer", "-mno-omit-leaf-frame-pointer", "-fwrapv", "-fstack-protector-strong", "-std=gnu17",
            "-fmacro-prefix-map=sys/=/usr/src/sys/", "-fdebug-prefix-map=sys/=/usr/src/sys/"] +
            policy.copts + KERNEL_WARNING_FLAGS + KERNEL_DEBUG_FLAGS + copts,
        local_defines = ["_KERNEL", "KLD_MODULE", "KLD_TIED", "HAVE_KERNEL_OPTION_HEADERS", "__printf__=__freebsd_kprintf__"],
        target_compatible_with = ["@platforms//os:freebsd", "@platforms//cpu:" + policy.cpu,
            "//tools/build/bazel/kernel_toolchain:kernel"])
    bsd_ctf_library(name = name + "_ctf", library = ":" + name + "_objects",
        converter = "//cddl/usr.bin/ctfconvert:ctfconvert", preserve_debug = True,
        ctf_label_setting = "//tools/build/bazel/config:kernel_ctf_label",
        enabled = select({"//tools/build/bazel/config:kernel_ctf_enabled": True, "//conditions:default": False}),
        runtime = ["//cddl/lib/libspl:spl_shared", "//lib/libdwarf:dwarf_shared", "//lib/libelf:elf_shared", "//lib/libz:z_shared",
            "@bsd_sdk//toolchain:sysroot/lib/libc.so.7", "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7"])
    native.filegroup(name = name + "_object_files", srcs = [":" + name + "_ctf"], output_group = "regular_objects",
        visibility = ["//visibility:public"])

def cross_generic_module(arch, module, objects, exports = [], export_all = False, package = "kernel"):
    policy = _ARCH[arch]
    kernel_module_artifacts(module = module, objects = objects, emulation = policy.emulation,
        shared = True, prefix = arch + "_", linkopts = policy.linkopts,
        exports = exports, export_all = export_all, package = package,
        linker_inputs = ["//tools/build/bazel/kernel_toolchain:link_inputs"])
