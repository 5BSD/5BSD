# SPDX-License-Identifier: BSD-2-Clause
"""Source-only CcInfo headers with physical, package-relative include roots."""
load("@bazel_skylib//lib:paths.bzl", "paths")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")

def _headers(ctx):
    if not ctx.files.hdrs or any([not f.is_source for f in ctx.files.hdrs]):
        fail("source header contexts require nonempty source-only headers")
    roots = []
    for directory in ctx.attr.includes:
        if paths.is_absolute(directory) or ".." in directory.split("/"):
            fail("source include roots must stay inside their owning package")
        root = paths.normalize(paths.join(ctx.label.workspace_root, ctx.label.package, directory))
        if not any([f.path.startswith(root + "/") for f in ctx.files.hdrs]):
            fail("source include root has no declared headers: " + root)
        roots.append(root)
    own = CcInfo(compilation_context = cc_common.create_compilation_context(
        headers = depset(ctx.files.hdrs), includes = depset(roots)))
    return [DefaultInfo(files = depset(ctx.files.hdrs)),
        cc_common.merge_cc_infos(direct_cc_infos = [own],
            cc_infos = [dep[CcInfo] for dep in ctx.attr.deps])]

bsd_source_headers = rule(implementation = _headers, attrs = {
    "hdrs": attr.label_list(allow_files = True, mandatory = True),
    "includes": attr.string_list(),
    "deps": attr.label_list(providers = [CcInfo]),
})
