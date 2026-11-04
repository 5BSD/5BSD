# SPDX-License-Identifier: BSD-2-Clause
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")

def _policy(ctx):
    output = ctx.actions.declare_file(ctx.label.name + ".json")
    ctx.actions.write(output, json.encode({"maximum": ctx.attr.maximum[BuildSettingInfo].value,
        "address": ctx.attr.address[BuildSettingInfo].value}) + "\n")
    return [DefaultInfo(files = depset([output]))]

inspection_policy = rule(implementation = _policy, attrs = {
    "maximum": attr.label(default = "//tools/build/bazel/config:loader_bios_max_size", providers = [BuildSettingInfo]),
    "address": attr.label(default = "//tools/build/bazel/config:loader_bios_address", providers = [BuildSettingInfo]),
})
