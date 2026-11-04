# SPDX-License-Identifier: BSD-2-Clause
"""Expose the selected image timestamp to the artifact test, without a second default."""
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")

def _epoch(ctx):
    output = ctx.actions.declare_file(ctx.label.name + ".txt")
    ctx.actions.write(output, ctx.attr.setting[BuildSettingInfo].value + "\n")
    return [DefaultInfo(files = depset([output]))]

image_epoch = rule(implementation = _epoch, attrs = {
    "setting": attr.label(default = "//tools/build/bazel/config:loader_source_date_epoch", providers = [BuildSettingInfo]),
})
