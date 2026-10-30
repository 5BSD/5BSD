# SPDX-License-Identifier: BSD-2-Clause
"""Generate getconf tables after the maintained name-conflict check."""
def _tables(ctx):
    checked = ctx.actions.declare_file(ctx.label.name + ".checked")
    common = [ctx.attr.awk[DefaultInfo].files_to_run, ctx.attr.redirect[DefaultInfo].files_to_run]
    ctx.actions.run(executable = ctx.executable.redirect,
        arguments = [checked.path, ctx.executable.awk.path, "-f", ctx.file.checker.path] + [f.path for f in ctx.files.conflict_inputs],
        inputs = [ctx.file.checker] + ctx.files.conflict_inputs, tools = common,
        outputs = [checked], env = {"LC_ALL": "C"}, mnemonic = "GetconfNameCheck")
    outputs = []
    for source in ctx.files.srcs:
        output = ctx.actions.declare_file(ctx.label.name + "/" + source.basename[:-6] + ".c")
        ctx.actions.run(executable = ctx.executable.redirect,
            arguments = [output.path, ctx.executable.awk.path, "-f", ctx.file.generator.path, source.path],
            inputs = [checked, ctx.file.generator, source], tools = common,
            outputs = [output], env = {"LC_ALL": "C"}, mnemonic = "GetconfTable")
        outputs.append(output)
    return [DefaultInfo(files = depset(outputs))]
getconf_tables = rule(implementation = _tables, attrs = {
    "srcs": attr.label_list(allow_files = [".gperf"], mandatory = True),
    "conflict_inputs": attr.label_list(allow_files = [".gperf"], mandatory = True),
    "checker": attr.label(allow_single_file = True, mandatory = True),
    "generator": attr.label(allow_single_file = True, mandatory = True),
    "awk": attr.label(executable = True, cfg = "exec", mandatory = True),
    "redirect": attr.label(executable = True, cfg = "exec", mandatory = True),
})
