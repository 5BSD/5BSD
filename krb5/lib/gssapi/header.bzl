# SPDX-License-Identifier: BSD-2-Clause
"""Generate the MIT GSSAPI public header from its declared vendor interface."""
def _impl(ctx):
    output = ctx.actions.declare_file("gssapi.h")
    prefix = ctx.actions.declare_file(ctx.label.name + ".prefix")
    ctx.actions.write(prefix, "/* This is the gssapi.h prologue. */\n/* no xom.h */\n/* End of gssapi.h prologue. */\n")
    ctx.actions.run(executable = ctx.executable.redirect,
        arguments = [output.path, ctx.executable.cat.path, prefix.path, ctx.file.interface.path],
        inputs = [prefix, ctx.file.interface], tools = [ctx.attr.cat[DefaultInfo].files_to_run] + ctx.files.runtime,
        outputs = [output], env = {"LC_ALL": "C"}, use_default_shell_env = False, mnemonic = "MITGSSAPIHeader")
    return [DefaultInfo(files = depset([output]))]
gssapi_header = rule(implementation = _impl, attrs = {
    "interface": attr.label(allow_single_file = True, mandatory = True),
    "cat": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "redirect": attr.label(executable = True, cfg = "exec", mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
})
