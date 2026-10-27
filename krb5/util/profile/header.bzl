# SPDX-License-Identifier: BSD-2-Clause
"""Join the vendor profile interface and generated error declarations."""
def _header(ctx):
    output = ctx.actions.declare_file("profile.h")
    ctx.actions.run(
        executable = ctx.executable.redirect,
        arguments = [output.path, ctx.executable.cat.path, ctx.file.interface.path, ctx.file.errors.path],
        inputs = [ctx.file.interface, ctx.file.errors],
        tools = [ctx.attr.cat[DefaultInfo].files_to_run] + ctx.files.runtime,
        outputs = [output], env = {"LC_ALL": "C"},
        use_default_shell_env = False, mnemonic = "MITProfileHeader",
    )
    return [DefaultInfo(files = depset([output]))]
profile_header = rule(implementation = _header, attrs = {
    "interface": attr.label(allow_single_file = True, mandatory = True),
    "errors": attr.label(allow_single_file = True, mandatory = True),
    "cat": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "redirect": attr.label(executable = True, cfg = "exec", mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
})
