# SPDX-License-Identifier: BSD-2-Clause
"""Typed BIOS console parameters shared by all platform-library compiler contexts."""
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")

def _parameters(ctx):
    port = ctx.attr.port[BuildSettingInfo].value
    speed = ctx.attr.speed[BuildSettingInfo].value
    if port < 0 or port > 65535:
        fail("BIOS COM port must fit the x86 I/O port address space")
    if speed <= 0 or speed > 2147483647:
        fail("BIOS COM speed must be a positive signed integer")
    return [CcInfo(compilation_context = cc_common.create_compilation_context(
        defines = depset(["COMPORT=" + str(port), "COMSPEED=" + str(speed)])))]

bios_console_parameters = rule(implementation = _parameters, attrs = {
    "port": attr.label(default = "//tools/build/bazel/config:loader_comconsole_port", providers = [BuildSettingInfo]),
    "speed": attr.label(default = "//tools/build/bazel/config:loader_comconsole_speed", providers = [BuildSettingInfo]),
})
