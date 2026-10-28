# SPDX-License-Identifier: BSD-2-Clause
"""Compile a declared capability database with an execution-platform tool."""
def _capdb(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    if not output.basename.endswith(".db"):
        fail("capability database output must end in .db")
    ctx.actions.run(
        executable = ctx.attr.compiler[DefaultInfo].files_to_run,
        arguments = ["-l" if ctx.attr.byte_order == "little" else "-b", "-f", output.path[:-3], ctx.file.source.path],
        inputs = [ctx.file.source], outputs = [output],
        env = {"LC_ALL": "C"}, use_default_shell_env = False,
        mnemonic = "BSDCapabilityDatabase",
    )
    return [DefaultInfo(files = depset([output]))]
bsd_capdb = rule(implementation = _capdb, attrs = {
    "source": attr.label(allow_single_file = True, mandatory = True),
    "output": attr.string(mandatory = True),
    "byte_order": attr.string(mandatory = True, values = ["little", "big"]),
    "compiler": attr.label(executable = True, cfg = "exec", mandatory = True),
})
