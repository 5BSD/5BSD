# SPDX-License-Identifier: BSD-2-Clause
"""Select one declared inspection DSO from an execution tool's runtime closure."""

def _impl(ctx):
    name = ctx.attr.library_name
    if not name or "/" in name or "\\" in name:
        fail("library_name must be a library basename without a path")
    candidates = [file for file in ctx.files.runtime if file.basename == name + ".so" or file.basename.startswith(name + ".so.")]
    if len(candidates) != 1:
        fail("one declared " + name + " inspection DSO required; provide an execution runtime containing it")
    return [DefaultInfo(files = depset(candidates), runfiles = ctx.runfiles(files = ctx.files.runtime))]

bsd_inspection_library = rule(implementation = _impl, attrs = {
    "runtime": attr.label_list(allow_files = True, mandatory = True, cfg = "exec"),
    "library_name": attr.string(mandatory = True),
})
