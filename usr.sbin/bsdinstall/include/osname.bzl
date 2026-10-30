# SPDX-License-Identifier: BSD-2-Clause
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
def _header(ctx):
    value = ctx.attr.osname[BuildSettingInfo].value
    if not value or any([c < " " for c in value.elems()]):
        fail("installer_osname must be nonempty and contain no control characters")
    output = ctx.actions.declare_file("opt_osname.h")
    ctx.actions.write(output, "#define OSNAME " + json.encode(value) + "\n")
    return [DefaultInfo(files = depset([output]))]
osname_header = rule(implementation = _header, attrs = {"osname": attr.label(providers = [BuildSettingInfo], mandatory = True)})
