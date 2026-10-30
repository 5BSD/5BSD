# SPDX-License-Identifier: BSD-2-Clause
"""Run the maintained syscall stub generator with declared execution inputs."""

def _generate(ctx):
    ctx.actions.run(
        executable = ctx.executable.redirect,
        arguments = [ctx.outputs.output.path, ctx.executable.shell.path,
                     ctx.file.generator.path] + ctx.attr.arguments,
        inputs = [ctx.file.generator],
        tools = [ctx.executable.shell, ctx.executable.redirect] + ctx.files.runtime,
        outputs = [ctx.outputs.output],
        env = {"LC_ALL": "C"},
        use_default_shell_env = False,
        mnemonic = "BSDSyscallAssembly",
    )
    return [DefaultInfo(files = depset([ctx.outputs.output]))]

bsd_syscall_asm = rule(
    implementation = _generate,
    attrs = {
        "generator": attr.label(allow_single_file = True, mandatory = True),
        "arguments": attr.string_list(mandatory = True),
        "output": attr.output(mandatory = True),
        "shell": attr.label(executable = True, cfg = "exec", allow_files = True, mandatory = True),
        "redirect": attr.label(executable = True, cfg = "exec", mandatory = True),
        "runtime": attr.label_list(allow_files = True),
    },
)
