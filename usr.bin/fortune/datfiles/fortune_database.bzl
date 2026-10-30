# SPDX-License-Identifier: BSD-2-Clause
"""Build fortune's portable index with the declared execution-platform strfile."""
def _database(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add_all(["-Cs", ctx.file.src.path, output.path])
    ctx.actions.run(
        executable = ctx.attr.compiler[DefaultInfo].files_to_run,
        arguments = [args],
        inputs = [ctx.file.src],
        outputs = [output],
        env = {"LC_ALL": "C"},
        use_default_shell_env = False,
        mnemonic = "BSDFortuneDatabase",
    )
    return [DefaultInfo(files = depset([output]))]

fortune_database = rule(implementation = _database, attrs = {
    "src": attr.label(allow_single_file = True, mandatory = True),
    "output": attr.string(mandatory = True),
    "compiler": attr.label(executable = True, cfg = "exec", mandatory = True),
})
