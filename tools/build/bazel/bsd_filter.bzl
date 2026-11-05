# SPDX-License-Identifier: BSD-2-Clause
"""Transform a declared file with an explicit tool and runtime closure."""

def _filter(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    environment = {"LC_ALL": "C"}
    if ctx.files.runtime_libraries:
        environment["LD_LIBRARY_PATH"] = ":".join(sorted(depset([f.dirname for f in ctx.files.runtime_libraries]).to_list()))
    ctx.actions.run(
        executable = ctx.executable.redirect,
        arguments = [output.path, ctx.executable.tool.path] + ctx.attr.arguments + [ctx.file.src.path],
        inputs = [ctx.file.src], tools = [ctx.attr.tool[DefaultInfo].files_to_run] + ctx.files.runtime + ctx.files.runtime_libraries,
        outputs = [output], env = environment, use_default_shell_env = False,
        mnemonic = "BSDFilter",
    )
    return [DefaultInfo(files = depset([output]))]

bsd_filter = rule(
    implementation = _filter,
    attrs = {
        "src": attr.label(allow_single_file = True, mandatory = True),
        "output": attr.string(mandatory = True),
        "tool": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "redirect": attr.label(executable = True, cfg = "exec", mandatory = True),
        "runtime": attr.label_list(allow_files = True, cfg = "exec"),
        "arguments": attr.string_list(),
        "runtime_libraries": attr.label_list(allow_files = True, cfg = "exec"),
    },
)
