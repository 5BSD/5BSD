# SPDX-License-Identifier: BSD-2-Clause
load("@bazel_skylib//lib:unittest.bzl", "analysistest", "asserts")
load("//tools/build/bazel:bsd_install.bzl", "BsdInstallManifestInfo")
load("//tools/build/bazel:bsd_kernel_module_installation.bzl", "BsdKernelModuleInfo", "BsdKernelModuleSetInfo")

def _paths(ctx):
    env = analysistest.begin(ctx)
    target = analysistest.target_under_test(env)
    rows = target[BsdInstallManifestInfo].records
    asserts.equals(env, sorted(ctx.attr.expected), sorted([r["destination"] for r in rows]))
    aliases = [r for r in rows if r["type"] == "symlink"]
    asserts.equals(env, 1, len(aliases))
    asserts.equals(env, "sample.ko", aliases[0]["link"])
    asserts.equals(env, ["package=oes"], aliases[0]["tags"])
    debug = [r for r in rows if r["destination"].endswith(".debug")]
    asserts.equals(env, ["package=oes", "dbg"], debug[0]["tags"])
    asserts.equals(env, 2, len(target[BsdInstallManifestInfo].payload.to_list()))
    return analysistest.end(env)

# These fixtures assert the default layout independently of the caller's build
# settings. The custom and inline fixtures below exercise their own explicit
# layouts; real complete-installation targets retain the caller's settings.
path_test = analysistest.make(_paths, config_settings = {
    str(Label("//tools/build/bazel/config:kernel_base_directory")): "/boot/kernel",
    str(Label("//tools/build/bazel/config:kernel_directory")): "/boot/modules",
    str(Label("//tools/build/bazel/config:kernel_debug_directory")): "/usr/lib/debug",
}, attrs = {"expected": attr.string_list(mandatory = True)})
custom_path_test = analysistest.make(_paths, config_settings = {
    str(Label("//tools/build/bazel/config:kernel_base_directory")): "/boot/custom",
    str(Label("//tools/build/bazel/config:kernel_directory")): "/third-party/modules",
    str(Label("//tools/build/bazel/config:kernel_debug_directory")): "/debug/custom",
}, attrs = {"expected": attr.string_list(mandatory = True)})
inline_debug_test = analysistest.make(_paths, config_settings = {
    str(Label("//tools/build/bazel/config:kernel_base_directory")): "/boot/inline",
    str(Label("//tools/build/bazel/config:kernel_debug_directory")): "",
}, attrs = {"expected": attr.string_list(mandatory = True)})

def _failure(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, ctx.attr.expected)
    return analysistest.end(env)
collision_test = analysistest.make(_failure, expect_failure = True,
    attrs = {"expected": attr.string(default = "duplicate installation destination")})
invalid_base_test = analysistest.make(_failure, expect_failure = True,
    config_settings = {str(Label("//tools/build/bazel/config:kernel_base_directory")): "relative/kernel"},
    attrs = {"expected": attr.string(default = "absolute directory without traversal")})
invalid_debug_test = analysistest.make(_failure, expect_failure = True,
    config_settings = {str(Label("//tools/build/bazel/config:kernel_debug_directory")): "/debug/../escape"},
    attrs = {"expected": attr.string(default = "absolute directory without traversal")})

def _fixture_product(ctx):
    return [DefaultInfo(files = depset([ctx.file.binary, ctx.file.debug])),
        BsdKernelModuleInfo(link_recipe = None, binary = ctx.file.binary, debug = ctx.file.debug,
                            aliases = ["alias.ko"], package = "oes",
                            file_metadata = dict(owner = "root", group = "wheel", mode = "0444", flags = ""),
                            alias_metadata = dict(owner = "root", group = "wheel", mode = "0755"))]
fixture_product = rule(implementation = _fixture_product, attrs = {
    "binary": attr.label(allow_single_file = True, mandatory = True),
    "debug": attr.label(allow_single_file = True, mandatory = True),
})

def _selected_count(ctx):
    env = analysistest.begin(ctx)
    info = analysistest.target_under_test(env)[BsdKernelModuleSetInfo]
    asserts.equals(env, ctx.attr.expected, len(info.members))
    asserts.equals(env, ctx.attr.expected * 2, len(info.payload.to_list()))
    return analysistest.end(env)
source_selection_test = analysistest.make(_selected_count, attrs = {"expected": attr.int(mandatory = True)})
