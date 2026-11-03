# SPDX-License-Identifier: BSD-2-Clause
"""Explicit compiler resources and selected system headers from the chosen SDK."""
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")

def _headers(ctx):
    resources = []
    roots = []
    for file in ctx.files.sdk_files:
        parts = file.path.split("/sysroot/usr/lib/clang/")
        if len(parts) != 2 or "/include/" not in parts[1]:
            continue
        version, relative = parts[1].split("/include/", 1)
        if not version or "/" in version or not relative:
            fail("malformed SDK compiler resource path: " + file.path)
        root = parts[0] + "/sysroot/usr/lib/clang/" + version + "/include"
        if root not in roots:
            roots.append(root)
        resources.append(file)
    if len(roots) != 1 or not resources:
        fail("exactly one declared SDK compiler resource directory is required")
    root = roots[0]
    sysroot = root.split("/usr/lib/clang/")[0]
    system_root = sysroot + "/usr/include"
    files = list(resources)
    if ctx.attr.resource_headers:
        files = []
        for relative in ctx.attr.resource_headers:
            if relative.startswith("/") or any([p in ["", ".", ".."] for p in relative.split("/")]):
                fail("SDK resource header must be a normalized relative path")
            matches = [f for f in resources if f.path == root + "/" + relative]
            if len(matches) != 1:
                fail("one declared SDK resource header required: " + relative)
            files.append(matches[0])
    for relative in ctx.attr.system_headers:
        if relative.startswith("/") or any([p in ["", ".", ".."] for p in relative.split("/")]):
            fail("SDK system header must be a normalized relative path")
        matches = [f for f in ctx.files.sdk_files if f.path == system_root + "/" + relative]
        if len(matches) != 1:
            fail("one declared SDK system header required: " + relative)
        files.append(matches[0])
    includes = [root] + ([system_root] if ctx.attr.system_headers else [])
    return [DefaultInfo(files = depset(files)), CcInfo(compilation_context =
        cc_common.create_compilation_context(headers = depset(files), system_includes = depset(includes)))]

bsd_sdk_headers = rule(implementation = _headers, attrs = {
    "sdk_files": attr.label(default = "@bsd_sdk//toolchain:compile_inputs", cfg = "exec"),
    "resource_headers": attr.string_list(doc = "Optional exact compiler resource headers; empty retains the complete resource set."),
    "system_headers": attr.string_list(doc = "Explicit additional headers relative to the selected SDK usr/include."),
})
