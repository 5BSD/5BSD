# SPDX-License-Identifier: BSD-2-Clause
"""LLVM registration definitions from selected backends and compiler platform."""
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")

_BACKENDS = {"aarch64": "AArch64", "arm": "ARM", "bpf": "BPF", "loongarch": "LoongArch", "powerpc": "PowerPC", "riscv": "RISCV", "x86": "X86"}
_CPUS = {"aarch64": "aarch64", "arm": "arm", "ppc": "powerpc", "riscv64": "riscv", "x86_32": "x86", "x86_64": "x86"}

def _impl(ctx):
    enabled = [name for name in _BACKENDS if getattr(ctx.attr, name)[BuildSettingInfo].value]
    if not enabled:
        fail("An installed LLVM compiler requires at least one enabled backend")
    defines = ["LLVM_TARGET_ENABLE_" + name.upper() for name in enabled]
    for cpu, backend in _CPUS.items():
        if backend in enabled and ctx.target_platform_has_constraint(getattr(ctx.attr, "cpu_" + cpu)[platform_common.ConstraintValueInfo]):
            for suffix in ["ASMPARSER", "ASMPRINTER", "DISASSEMBLER", "TARGET", "TARGETINFO", "TARGETMC"]:
                entry = {"ASMPARSER": "AsmParser", "ASMPRINTER": "AsmPrinter", "DISASSEMBLER": "Disassembler", "TARGET": "Target", "TARGETINFO": "TargetInfo", "TARGETMC": "TargetMC"}[suffix]
                defines.append("LLVM_NATIVE_" + suffix + "=LLVMInitialize" + _BACKENDS[backend] + entry)
    return [CcInfo(compilation_context = cc_common.create_compilation_context(defines = depset(defines)))]

bsd_llvm_targets = rule(implementation = _impl, attrs =
    {name: attr.label(default = "//tools/build/bazel/config:llvm_target_" + name, providers = [BuildSettingInfo]) for name in _BACKENDS} |
    {"cpu_" + cpu: attr.label(default = "@platforms//cpu:" + cpu, providers = [platform_common.ConstraintValueInfo]) for cpu in _CPUS})
