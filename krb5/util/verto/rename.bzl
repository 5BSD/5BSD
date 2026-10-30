# SPDX-License-Identifier: BSD-2-Clause
"""Generate the embedded libev symbol namespace from its maintained inventory."""
def _impl(ctx):
    output = ctx.actions.declare_file("rename.h")
    ctx.actions.run(
        executable = ctx.executable.redirect,
        arguments = [output.path, ctx.executable.awk.path,
                     '{ print "#define " $0 " k5" $0 }', ctx.file.symbols.path],
        inputs = [ctx.file.symbols],
        tools = [ctx.attr.awk[DefaultInfo].files_to_run] + ctx.files.runtime,
        outputs = [output],
        env = {"LC_ALL": "C"},
        use_default_shell_env = False,
        mnemonic = "VertoSymbolNamespace",
    )
    return [DefaultInfo(files = depset([output]))]
verto_rename = rule(implementation = _impl, attrs = {
    "symbols": attr.label(allow_single_file = True, mandatory = True),
    "awk": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "redirect": attr.label(executable = True, cfg = "exec", mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
})
