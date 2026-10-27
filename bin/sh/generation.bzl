# SPDX-License-Identifier: BSD-2-Clause
"""Declared native shell generators with grouped outputs and path arguments."""
def _generate(ctx):
    outputs = ctx.outputs.outputs
    if not outputs or any([f.dirname != outputs[0].dirname for f in outputs]):
        fail("generator outputs must share one declared directory")
    args = [ctx.file.runner.path, "--output-dir", outputs[0].dirname, "--tool", ctx.executable.tool.path]
    inputs = [ctx.file.runner, ctx.file.python_home] + ctx.files.inputs + ctx.files.argument_files + ctx.files.runtime
    tools = [ctx.attr.tool[DefaultInfo].files_to_run]
    for file in ctx.files.argument_files:
        args += ["--argument", file.path]
    if ctx.file.argument_directory:
        inputs.append(ctx.file.argument_directory)
        args += ["--argument", ctx.file.argument_directory.dirname]
    names = []
    for tool, name in ctx.attr.path_tools.items():
        if not name or "/" in name or name in [".", ".."] or name in names:
            fail("generator tool aliases require unique basenames")
        names.append(name)
        files = tool[DefaultInfo].files.to_list()
        if len(files) != 1:
            fail("one executable per generator PATH entry required")
        alias = ctx.actions.declare_file(ctx.label.name + ".tools/" + name)
        ctx.actions.symlink(output = alias, target_file = files[0], is_executable = True)
        inputs.append(alias)
        tools.append(tool[DefaultInfo].files_to_run)
        if len(names) == 1:
            args += ["--tool-path", alias.dirname]
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = args, inputs = inputs, tools = tools, outputs = outputs,
        env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1", "LC_ALL": "C"},
        use_default_shell_env = False, mnemonic = "BSDShellGenerate")
    return [DefaultInfo(files = depset(outputs))]

shell_generate = rule(implementation = _generate, attrs = {
    "outputs": attr.output_list(mandatory = True),
    "tool": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "argument_files": attr.label_list(allow_files = True),
    "argument_directory": attr.label(allow_single_file = True),
    "inputs": attr.label_list(allow_files = True),
    "path_tools": attr.label_keyed_string_dict(cfg = "exec", allow_files = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
    "runner": attr.label(allow_single_file = True, default = ":generator.py"),
    "python": attr.label(executable = True, cfg = "exec", allow_single_file = True, default = "@bsd_sdk//toolchain:extra_python"),
    "python_home": attr.label(allow_single_file = True, default = "@bsd_sdk//toolchain:python-home/runtime.json"),
})
