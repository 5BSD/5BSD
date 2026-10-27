# SPDX-License-Identifier: BSD-2-Clause
"""Run the maintained fidlc schema generator with declared tools."""
def _schema(ctx):
    output = ctx.actions.declare_file("json_schema.cc")
    cat = ctx.actions.declare_file(ctx.label.name + "_tools/cat")
    ctx.actions.symlink(output = cat, target_file = ctx.executable.cat, is_executable = True)
    ctx.actions.run(executable = ctx.executable.shell,
        arguments = [ctx.file.script.path, output.path, ctx.file.schema.path],
        inputs = [ctx.file.script, ctx.file.schema],
        tools = [cat, ctx.executable.cat] + ctx.files.runtime, outputs = [output],
        env = {"PATH": cat.dirname, "LC_ALL": "C"}, use_default_shell_env = False,
        mnemonic = "BSDFidlSchema")
    return [DefaultInfo(files = depset([output]))]
fidl_schema = rule(implementation = _schema, attrs = {
    "script": attr.label(allow_single_file = True, mandatory = True),
    "schema": attr.label(allow_single_file = True, mandatory = True),
    "shell": attr.label(executable = True, cfg = "exec", mandatory = True, allow_single_file = True),
    "cat": attr.label(executable = True, cfg = "exec", mandatory = True, allow_single_file = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
})
