# SPDX-License-Identifier: BSD-2-Clause
"""Loader Lua paths as typed Bazel configuration, independent of host paths."""
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")

def _paths(ctx):
    path = ctx.attr.path[BuildSettingInfo].value
    if not path.startswith("/") or "\n" in path or "\r" in path or "\000" in path:
        fail("loader Lua path must be an absolute path without NUL or newlines")
    # CcInfo defines are compiler operands, without shell expansion or quoting.
    definitions = ["LUA_PATH=" + json.encode(path), "LUA_PATH_DEFAULT=" + json.encode(path + "/?.lua")]
    return [CcInfo(compilation_context = cc_common.create_compilation_context(defines = depset(definitions)))]

loader_lua_paths = rule(implementation = _paths, attrs = {
    "path": attr.label(default = "//tools/build/bazel/config:loader_lua_path", providers = [BuildSettingInfo]),
})
