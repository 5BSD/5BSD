# SPDX-License-Identifier: BSD-2-Clause
"""One configured address controls the BTX loader code, origin and final entry."""
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")

def _address(ctx):
    value = ctx.attr.address[BuildSettingInfo].value
    if type(value) != "int" or value < 0 or value > 4294967295:
        fail("BIOS loader address must fit an unsigned 32-bit value")
    return [CcInfo(compilation_context = cc_common.create_compilation_context(
        defines = depset(["LOADER_ADDRESS=" + str(value)])))]

loader_address = rule(implementation = _address, attrs = {
    "address": attr.label(default = "//tools/build/bazel/config:loader_bios_address", providers = [BuildSettingInfo]),
})
