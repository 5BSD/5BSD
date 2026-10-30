# SPDX-License-Identifier: BSD-2-Clause
"""Declared libmd high-level API generation using its maintained source script."""

def _highlevel(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add(ctx.file._script)
    args.add_all([str(ctx.attr.digest_bytes), ctx.attr.header, ctx.attr.symbol, ctx.attr.context])
    args.add_all([ctx.file._template, output, ctx.executable.sed, ctx.executable.mv, ctx.executable.rm])
    ctx.actions.run(
        executable = ctx.attr.shell[DefaultInfo].files_to_run,
        arguments = [args],
        inputs = [ctx.file._script, ctx.file._template],
        tools = [ctx.attr.sed[DefaultInfo].files_to_run, ctx.attr.mv[DefaultInfo].files_to_run, ctx.attr.rm[DefaultInfo].files_to_run] + ctx.files.runtime,
        outputs = [output],
        env = {"LC_ALL": "C"},
        use_default_shell_env = False,
        mnemonic = "LibmdHighLevel",
    )
    return [DefaultInfo(files = depset([output]))]

libmd_highlevel = rule(
    implementation = _highlevel,
    attrs = {
        "output": attr.string(mandatory = True),
        "digest_bytes": attr.int(mandatory = True),
        "header": attr.string(mandatory = True),
        "symbol": attr.string(mandatory = True),
        "context": attr.string(default = "-"),
        "shell": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "sed": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "mv": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "rm": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "runtime": attr.label_list(cfg = "exec", allow_files = True),
        "_script": attr.label(default = Label(":genhl.sh"), allow_single_file = True, cfg = "exec"),
        "_template": attr.label(default = Label(":mdXhl.c"), allow_single_file = True),
    },
)

def _manual(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add_all([ctx.file._script, ctx.attr.lower, ctx.attr.upper,
                  ctx.file.template, ctx.file.copyright, output,
                  ctx.executable.sed, ctx.executable.cat,
                  ctx.executable.mv, ctx.executable.rm])
    ctx.actions.run(
        executable = ctx.attr.shell[DefaultInfo].files_to_run,
        arguments = [args],
        inputs = [ctx.file._script, ctx.file.template, ctx.file.copyright],
        tools = [t[DefaultInfo].files_to_run for t in [ctx.attr.sed, ctx.attr.cat, ctx.attr.mv, ctx.attr.rm]] + ctx.files.runtime,
        outputs = [output], env = {"LC_ALL": "C"}, use_default_shell_env = False,
        mnemonic = "LibmdManual",
    )
    return [DefaultInfo(files = depset([output]))]

libmd_manual = rule(
    implementation = _manual,
    attrs = {
        "output": attr.string(mandatory = True),
        "lower": attr.string(mandatory = True),
        "upper": attr.string(mandatory = True),
        "template": attr.label(allow_single_file = True, mandatory = True),
        "copyright": attr.label(allow_single_file = True, mandatory = True),
        "shell": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "sed": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "cat": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "mv": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "rm": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "runtime": attr.label_list(cfg = "exec", allow_files = True),
        "_script": attr.label(default = Label(":genman.sh"), allow_single_file = True, cfg = "exec"),
    },
)
