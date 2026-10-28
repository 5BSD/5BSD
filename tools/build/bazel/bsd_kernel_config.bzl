# SPDX-License-Identifier: BSD-2-Clause
"""Run native config with declared configuration metadata and a complete output tree."""
def _impl(ctx):
    output = ctx.actions.declare_directory(ctx.label.name + ".generated")
    args = ctx.actions.args()
    args.add_all(["-B", ctx.file.runner.path, ctx.executable.tool.path,
                  ctx.file.config.path, ctx.file.source_anchor.path, output.path])
    args.add("1" if ctx.attr.debug else "0")
    args.add_all(ctx.files.libraries)
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = [args],
        inputs = [ctx.file.runner, ctx.file.config, ctx.file.source_anchor, ctx.file.python_home] + ctx.files.inputs + ctx.files.runtime + ctx.files.libraries,
        tools = [ctx.attr.tool[DefaultInfo].files_to_run], outputs = [output],
        env = {"LC_ALL": "C", "PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1"},
        use_default_shell_env = False, mnemonic = "BSDKernelConfig")
    return [DefaultInfo(files = depset([output]))]

bsd_kernel_config = rule(implementation = _impl, attrs = {
    "config": attr.label(allow_single_file = True, mandatory = True),
    "inputs": attr.label_list(allow_files = True, mandatory = True),
    "source_anchor": attr.label(allow_single_file = True, mandatory = True, doc = "The kernel conf/files input; its parent's parent identifies the source root."),
    "debug": attr.bool(),
    "tool": attr.label(executable = True, cfg = "exec", default = "//usr.sbin/config:config"),
    "runner": attr.label(allow_single_file = True, default = "//tools/build/bazel:kernel_config.py"),
    "libraries": attr.label_list(allow_files = True, cfg = "exec"),
    "python": attr.label(executable = True, allow_single_file = True, cfg = "exec", mandatory = True),
    "python_home": attr.label(allow_single_file = True, cfg = "exec", mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
})
