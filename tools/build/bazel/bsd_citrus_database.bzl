# SPDX-License-Identifier: BSD-2-Clause
"""Compile a declared Citrus database using an execution-platform tool."""
def _database(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    if ctx.attr.mode == "lookup":
        args.add("-m")
    elif ctx.attr.mode == "pivot":
        args.add("-p")
    args.add("-o", output)
    args.add(ctx.file.src)
    ctx.actions.run(
        executable = ctx.executable.tool,
        arguments = [args],
        inputs = [ctx.file.src],
        outputs = [output],
        env = {"LC_ALL": "C"},
        use_default_shell_env = False,
        mnemonic = "CitrusDatabase",
    )
    return [DefaultInfo(files = depset([output]))]

citrus_database = rule(implementation = _database, attrs = {
    "src": attr.label(allow_single_file = True, mandatory = True),
    "output": attr.string(mandatory = True),
    "mode": attr.string(default = "compile", values = ["compile", "lookup", "pivot"]),
    "tool": attr.label(executable = True, cfg = "exec", mandatory = True),
})
