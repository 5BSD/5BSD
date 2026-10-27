# SPDX-License-Identifier: BSD-2-Clause
"""Declared generation of the protocol error tables; no Make or shell pipeline."""
def _table(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add_all(["-B", "-S", ctx.file._generator.path, ctx.file.source.path, output.path, ctx.attr.protocol])
    ctx.actions.run(
        executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = [args],
        inputs = [ctx.file.source, ctx.file._generator, ctx.file.python_home],
        tools = ctx.files.runtime,
        outputs = [output],
        env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1", "LC_ALL": "C"},
        use_default_shell_env = False,
        mnemonic = "FetchErrorTable",
    )
    return [DefaultInfo(files = depset([output]))]

fetch_error_table = rule(implementation = _table, attrs = {
    "source": attr.label(allow_single_file = True, mandatory = True),
    "output": attr.string(mandatory = True),
    "protocol": attr.string(values = ["ftp", "http"], mandatory = True),
    "python": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "python_home": attr.label(cfg = "exec", allow_single_file = True, mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
    "_generator": attr.label(default = Label("//lib/libfetch:error_table.py"), allow_single_file = True),
})
