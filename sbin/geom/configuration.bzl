# SPDX-License-Identifier: BSD-2-Clause
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
def _impl(ctx):
    path = ctx.attr.path[BuildSettingInfo].value
    if not path.startswith("/") or any([c < " " for c in path.elems()]):
        fail("GEOM class directory must be an absolute path without control characters")
    out = ctx.actions.declare_file("geom_configuration.h")
    ctx.actions.write(out, "#define GEOM_CLASS_DIR " + json.encode(path) + "\n")
    return [DefaultInfo(files = depset([out]))]
geom_configuration = rule(implementation = _impl, attrs = {"path": attr.label(mandatory = True)})
