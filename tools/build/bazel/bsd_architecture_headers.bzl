# SPDX-License-Identifier: BSD-2-Clause
"""Declared architecture header view, preserving machine/../<sibling> includes."""
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")


def _headers(ctx):
    aliases = []
    seen = {}
    root = None
    for target, directory in ctx.attr.headers.items():
        if not directory or directory.startswith("/") or any([p in ["", ".", ".."] for p in directory.split("/")]):
            fail("architecture header directory must be relative without traversal")
        for file in target[DefaultInfo].files.to_list():
            name = directory + "/" + file.basename
            if name in seen:
                fail("duplicate architecture header view path: " + name)
            seen[name] = True
            alias = ctx.actions.declare_file(ctx.label.name + ".includes/" + name)
            ctx.actions.symlink(output = alias, target_file = file)
            if root == None:
                root = alias.path[:-len(name)].rstrip("/")
            aliases.append(alias)
    if not aliases:
        fail("architecture header view must not be empty")
    return [DefaultInfo(files = depset(aliases)), CcInfo(compilation_context = cc_common.create_compilation_context(
        headers = depset(aliases), includes = depset([root])))]

bsd_architecture_headers = rule(implementation = _headers, attrs = {
    "headers": attr.label_keyed_string_dict(allow_files = True, mandatory = True),
})
