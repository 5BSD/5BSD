# SPDX-License-Identifier: BSD-2-Clause
"""Explicit dependency identity; does not assert a package artifact exists."""
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")

BsdPackageDependencyInfo = provider(fields = ["package", "origin", "version"])

def _dependency(ctx):
    version = ctx.attr.version[BuildSettingInfo].value
    for value in [ctx.attr.package, version]:
        if not value or any([c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.+,-" for c in value.elems()]):
            fail("valid explicit package name and version required")
    origin = ctx.attr.origin
    if len(origin.split("/")) != 2 or any([part in ["", ".", ".."] for part in origin.split("/")]) or any([c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.+,-/" for c in origin.elems()]):
        fail("explicit category/package origin required")
    return [DefaultInfo(files = depset()), BsdPackageDependencyInfo(package = ctx.attr.package, origin = origin, version = version)]

bsd_pkg_dependency = rule(
    implementation = _dependency,
    attrs = {
        "package": attr.string(mandatory = True),
        "origin": attr.string(mandatory = True),
        "version": attr.label(providers = [BuildSettingInfo], mandatory = True),
    },
)
