# SPDX-License-Identifier: BSD-2-Clause
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")

def _policy(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".json")
    ctx.actions.write(out, json.encode({name: getattr(ctx.attr, name)[BuildSettingInfo].value for name in ["maximum", "address", "man", "compressed", "split"]}) + "\n")
    return [DefaultInfo(files = depset([out]))]

pxe_inspection = rule(implementation = _policy, attrs = {
    "maximum": attr.label(default = "//tools/build/bazel/config:loader_pxe_max_size", providers = [BuildSettingInfo]),
    "address": attr.label(default = "//tools/build/bazel/config:loader_bios_address", providers = [BuildSettingInfo]),
    "man": attr.label(default = "//tools/build/bazel/config:man", providers = [BuildSettingInfo]),
    "compressed": attr.label(default = "//tools/build/bazel/config:mancompress", providers = [BuildSettingInfo]),
    "split": attr.label(default = "//tools/build/bazel/config:split_manpages", providers = [BuildSettingInfo]),
})
