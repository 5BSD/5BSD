# SPDX-License-Identifier: BSD-2-Clause
def _list(ctx):
    out = ctx.actions.declare_file(ctx.label.name + "/list.h")
    args = ctx.actions.args()
    args.add_all(["-B", "-S", ctx.file._script.path])
    for name in ctx.attr.exclude:
        args.add_all(["--exclude", name])
    args.add(out.path)
    args.add_all(ctx.files.srcs)
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = [args], inputs = ctx.files.srcs + [ctx.file._script, ctx.file.python_home],
        tools = ctx.files.runtime, outputs = [out],
        env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1", "LC_ALL": "C"},
        use_default_shell_env = False, mnemonic = "LibarchiveTestRegistry")
    return [DefaultInfo(files = depset([out]))]
archive_test_list = rule(implementation = _list, attrs = {
    "exclude": attr.string_list(doc = "Original literal BROKEN_TESTS fragments, excluded before registration."),
    "srcs": attr.label_list(allow_files = [".c"], mandatory = True),
    "python": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "python_home": attr.label(allow_single_file = True, mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
    "_script": attr.label(default = Label(":test_list.py"), allow_single_file = True),
})
