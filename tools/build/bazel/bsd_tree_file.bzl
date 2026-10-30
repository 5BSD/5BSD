# SPDX-License-Identifier: BSD-2-Clause
"""Expose one generated directory member as an independently hashed artifact."""
def _impl(ctx):
    if not ctx.file.tree.is_directory:
        fail("tree must be a declared directory artifact")
    member = ctx.attr.member
    if not member or "\\" in member or any([p in ["", ".", ".."] for p in member.split("/")]):
        fail("member must be a normalized relative path")
    output = ctx.actions.declare_file(ctx.attr.output)
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = ["-B", ctx.file._extract.path, ctx.file.tree.path, member, output.path],
        inputs = [ctx.file.tree, ctx.file._extract, ctx.file.python_home] + ctx.files.runtime,
        outputs = [output], env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1"},
        use_default_shell_env = False, mnemonic = "BSDTreeFile")
    return [DefaultInfo(files = depset([output]))]

bsd_tree_file = rule(implementation = _impl, attrs = {
    "tree": attr.label(allow_single_file = True, mandatory = True),
    "member": attr.string(mandatory = True),
    "output": attr.string(mandatory = True),
    "python": attr.label(executable = True, allow_single_file = True, cfg = "exec", mandatory = True),
    "python_home": attr.label(allow_single_file = True, cfg = "exec", mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
    "_extract": attr.label(allow_single_file = True, default = Label(":tree_file.py")),
})
