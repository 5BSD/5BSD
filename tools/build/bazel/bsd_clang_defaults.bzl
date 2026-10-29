# SPDX-License-Identifier: BSD-2-Clause
"""Produced compiler defaults, independent of build SDK paths."""
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")
load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain", "use_cc_toolchain")

def _impl(ctx):
    triple = find_cc_toolchain(ctx).target_gnu_system_name
    values = [("LLVM_HOST_TRIPLE", ctx.attr.host[BuildSettingInfo].value or triple), ("LLVM_DEFAULT_TARGET_TRIPLE", ctx.attr.target[BuildSettingInfo].value or triple), ("DEFAULT_SYSROOT", ctx.attr.sysroot[BuildSettingInfo].value)]
    defines = []
    for name, value in values:
        if "\n" in value or "\r" in value:
            fail(name + " cannot contain a newline")
        defines.append(name + "=" + json.encode(value))
    return [CcInfo(compilation_context = cc_common.create_compilation_context(defines = depset(defines)))]

bsd_clang_defaults = rule(
    implementation = _impl,
    attrs = {
        "host": attr.label(default = "//tools/build/bazel/config:llvm_host_triple", providers = [BuildSettingInfo]),
        "target": attr.label(default = "//tools/build/bazel/config:llvm_default_target_triple", providers = [BuildSettingInfo]),
        "sysroot": attr.label(default = "//tools/build/bazel/config:llvm_default_sysroot", providers = [BuildSettingInfo]),
    },
    toolchains = use_cc_toolchain(),
    fragments = ["cpp"],
)
