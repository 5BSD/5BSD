# SPDX-License-Identifier: BSD-2-Clause
"""Generate libelf conversions with the maintained m4 templates."""
def _generate(ctx):
    out = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add_all([out.path, ctx.executable.m4.path, "-D", "SRCDIR=" + ctx.file.types.dirname, ctx.file.template.path])
    ctx.actions.run(executable = ctx.executable.redirect, arguments = [args],
        inputs = [ctx.file.types, ctx.file.template], tools = [ctx.attr.m4[DefaultInfo].files_to_run] + ctx.files.runtime,
        outputs = [out], env = {"LC_ALL": "C"}, use_default_shell_env = False, mnemonic = "LibelfM4")
    return [DefaultInfo(files = depset([out]))]
libelf_generate = rule(implementation = _generate, attrs = {
    "template": attr.label(allow_single_file = True, mandatory = True),
    "types": attr.label(allow_single_file = True, mandatory = True),
    "output": attr.string(mandatory = True),
    "m4": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "redirect": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
})
