# SPDX-License-Identifier: BSD-2-Clause
"""Typed serial policy for small GPT/ISO BIOS boot compiler contexts."""
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")

def _parameters(ctx):
    port = ctx.attr.port[BuildSettingInfo].value
    speed = ctx.attr.speed[BuildSettingInfo].value
    serial_format = ctx.attr.serial_format[BuildSettingInfo].value
    if port < 0 or port > 65535:
        fail("BIOS serial port must fit the x86 I/O address space")
    if speed <= 0 or speed > 2147483647:
        fail("BIOS serial speed must be a positive signed integer")
    if serial_format < 0 or serial_format > 255:
        fail("BIOS serial format must fit the UART line-control byte")
    return [CcInfo(compilation_context = cc_common.create_compilation_context(
        defines = depset(["SIOPRT=" + str(port), "SIOSPD=" + str(speed), "SIOFMT=" + str(serial_format)])))]

boot_console_parameters = rule(implementation = _parameters, attrs = {
    "port": attr.label(default = "//tools/build/bazel/config:loader_comconsole_port", providers = [BuildSettingInfo]),
    "speed": attr.label(default = "//tools/build/bazel/config:loader_comconsole_speed", providers = [BuildSettingInfo]),
    "serial_format": attr.label(default = "//tools/build/bazel/config:loader_boot_serial_format", providers = [BuildSettingInfo]),
})


def _inspection(ctx):
    output = ctx.actions.declare_file(ctx.label.name + ".json")
    ctx.actions.write(output, json.encode({"maximum": ctx.attr.maximum[BuildSettingInfo].value, "man": ctx.attr.man[BuildSettingInfo].value,
        "compressed": ctx.attr.compressed[BuildSettingInfo].value, "split": ctx.attr.split[BuildSettingInfo].value}) + "\n")
    return [DefaultInfo(files = depset([output]))]

boot_image_inspection = rule(implementation = _inspection, attrs = {
    "man": attr.label(default = "//tools/build/bazel/config:man", providers = [BuildSettingInfo]),
    "compressed": attr.label(default = "//tools/build/bazel/config:mancompress", providers = [BuildSettingInfo]),
    "split": attr.label(default = "//tools/build/bazel/config:split_manpages", providers = [BuildSettingInfo]),
    "maximum": attr.label(default = "//tools/build/bazel/config:loader_isoboot_max_size", providers = [BuildSettingInfo]),
})
