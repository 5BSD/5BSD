# SPDX-License-Identifier: BSD-2-Clause
"""Expand a Citrus encoding template with its declared variable table."""
def _encoding(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    ctx.actions.run(executable = ctx.executable.awk,
        arguments = ["-v", "key=" + ctx.attr.key, "-v", "encoding=" + ctx.attr.encoding,
            "-v", "output=" + output.path, "-f", ctx.file.script.path,
            ctx.file.variables.path, ctx.file.template.path],
        inputs = [ctx.file.script, ctx.file.variables, ctx.file.template], outputs = [output],
        env = {"LC_ALL": "C"}, use_default_shell_env = False, mnemonic = "CitrusEncoding")
    return [DefaultInfo(files = depset([output]))]

citrus_encoding = rule(implementation = _encoding, attrs = {
    "template": attr.label(allow_single_file = True, mandatory = True),
    "variables": attr.label(allow_single_file = True, mandatory = True),
    "script": attr.label(allow_single_file = True, mandatory = True),
    "key": attr.string(mandatory = True), "encoding": attr.string(mandatory = True),
    "output": attr.string(mandatory = True),
    "awk": attr.label(executable = True, cfg = "exec", mandatory = True),
})
