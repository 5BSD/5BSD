# SPDX-License-Identifier: BSD-2-Clause
"""Run the configured Heimdal header generator in the execution platform."""

def _header(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    ctx.actions.run(
        executable = ctx.executable.redirect,
        arguments = [output.path, ctx.executable.tool.path],
        tools = [ctx.attr.tool[DefaultInfo].files_to_run],
        outputs = [output],
        env = {"LC_ALL": "C"},
        use_default_shell_env = False,
        mnemonic = "HeimdalRokenHeader",
    )
    return [DefaultInfo(files = depset([output]))]

roken_header = rule(implementation = _header, attrs = {
    "tool": attr.label(executable = True, cfg = "exec", mandatory = True),
    "redirect": attr.label(executable = True, cfg = "exec", mandatory = True),
    "output": attr.string(mandatory = True),
})
