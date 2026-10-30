# SPDX-License-Identifier: BSD-2-Clause
"""Declared nscd configuration-path header from the maintained PREFIX input."""
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
def _header(ctx):
    prefix = ctx.attr.prefix[BuildSettingInfo].value
    if prefix and not prefix.startswith("/"):
        fail("nscd_prefix must be empty or an absolute path")
    if any([c < " " for c in prefix.elems()]):
        fail("invalid control character in nscd_prefix")
    output = ctx.actions.declare_file("nscd_build_config.h")
    ctx.actions.write(output, "/* Generated from nscd_prefix. */\n#define CONFIG_PATH " + json.encode(prefix + "/etc/nscd.conf") + "\n")
    return [DefaultInfo(files = depset([output]))]
config_path_header = rule(implementation = _header, attrs = {
    "prefix": attr.label(providers = [BuildSettingInfo], mandatory = True),
})
