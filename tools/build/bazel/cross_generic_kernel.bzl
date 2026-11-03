# SPDX-License-Identifier: BSD-2-Clause
"""Native ARM64/RISC-V built-in kernel objects; no loadable-module ABI flags."""
load("@rules_cc//cc:defs.bzl", "cc_library")
load(":kernel_common.bzl", "KERNEL_COMMON_WARNING_FLAGS", "KERNEL_DEBUG_FLAGS")
load(":bsd_ctf.bzl", "bsd_ctf_library")

_ARCH = {
    "arm64": struct(cpu = "aarch64", flags = [
        "-mstack-protector-guard=sysreg", "-mstack-protector-guard-reg=sp_el0",
        "-mstack-protector-guard-offset=0", "-fno-omit-frame-pointer",
        "-mno-omit-leaf-frame-pointer", "-ffixed-x18",
        "-mbranch-protection=standard", "-mno-outline-atomics"],
        headers = ["//sys/arm/include:kernel_headers", "//sys/dts:linux_dts_version_headers"],
        forced_headers = ["//sys/dts:linux_dts_version"]),
    "riscv": struct(cpu = "riscv64", flags = ["-fPIE", "-fno-omit-frame-pointer",
        "-fno-optimize-sibling-calls", "-march=rv64imafdch_zifencei_svinval",
        "-mabi=lp64", "-mno-relax", "-mcmodel=medium"], headers = [], forced_headers = []),
}

def cross_generic_kernel_objects(arch, name, srcs, deps = [], copts = [],
        early_deps = [], header_overrides = [], warning_flags = None,
        stack_protector = True, general_regs_only = True, features = [],
        pre_copts = [], additional_compiler_inputs = [], textual_hdrs = [], convert_ctf = True):
    """Compile source-owned built-ins with explicit per-owner policy exceptions."""
    policy = _ARCH[arch]
    name = arch + "_" + name
    headers = ["//sys/" + arch + "/conf:generic_global_headers",
        "//sys/" + arch + "/include:kernel_headers", "//sys/sys:kernel_headers",
        "//sys/bsm:kernel_headers", "//sys/kern:" + arch + "_generic_offset_header",
        "//sys/kern:vnode_headers"] + policy.headers
    forced = [flag for header in policy.forced_headers for flag in ["-include", "$(execpath " + header + ")"]]
    flags = ["-fno-strict-aliasing", "-include", "opt_global.h", "-fno-common"] + forced + policy.flags
    if arch == "arm64" and general_regs_only:
        flags += ["-mgeneral-regs-only"]
    flags += ["-fwrapv"] + (["-fstack-protector-strong"] if stack_protector else [])
    warnings = KERNEL_COMMON_WARNING_FLAGS if warning_flags == None else warning_flags
    cc_library(name = name + "_objects", srcs = srcs,
        deps = early_deps + header_overrides + [h for h in headers if h not in header_overrides] + deps,
        textual_hdrs = textual_hdrs + policy.forced_headers,
        additional_compiler_inputs = additional_compiler_inputs + textual_hdrs + policy.forced_headers,
        copts = pre_copts + flags + KERNEL_DEBUG_FLAGS + warnings + ["-std=gnu17"] +
            select({"//tools/build/bazel/config:werror_enabled": ["-Werror"], "//conditions:default": []}) +
            ["-fmacro-prefix-map=sys/=/usr/src/sys/", "-fdebug-prefix-map=sys/=/usr/src/sys/"] + copts,
        local_defines = ["_KERNEL", "HAVE_KERNEL_OPTION_HEADERS", "__printf__=__freebsd_kprintf__"],
        features = features,
        target_compatible_with = ["@platforms//os:freebsd", "@platforms//cpu:" + policy.cpu,
            "//tools/build/bazel/kernel_toolchain:kernel"])
    bsd_ctf_library(name = name + "_ctf", library = ":" + name + "_objects",
        converter = "//cddl/usr.bin/ctfconvert:ctfconvert", preserve_debug = True,
        ctf_label_setting = "//tools/build/bazel/config:kernel_ctf_label",
        enabled = select({"//tools/build/bazel/config:kernel_ctf_enabled": True,
            "//conditions:default": False}) if convert_ctf else False,
        runtime = ["//cddl/lib/libspl:spl_shared", "//lib/libdwarf:dwarf_shared",
            "//lib/libelf:elf_shared", "//lib/libz:z_shared",
            "@bsd_sdk//toolchain:execution-runtime/lib/libc.so.7",
            "@bsd_sdk//toolchain:execution-runtime/lib/libsys.so.7"])
    native.filegroup(name = name + "_object_files", srcs = [":" + name + "_ctf"],
        output_group = "regular_objects", visibility = ["//visibility:public"])
