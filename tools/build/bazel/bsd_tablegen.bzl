# SPDX-License-Identifier: BSD-2-Clause
"""LLVM TableGen actions with explicit execution tools and include inputs."""

def _impl(ctx):
    out = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add_all(ctx.attr.flags)
    args.add_all(ctx.attr.include_dirs, before_each = "-I")
    args.add("-o", out)
    args.add(ctx.file.src)
    ctx.actions.run(
        executable = ctx.attr.tool[DefaultInfo].files_to_run,
        arguments = [args],
        inputs = depset([ctx.file.src] + ctx.files.includes),
        outputs = [out],
        env = {"LC_ALL": "C"},
        use_default_shell_env = False,
        mnemonic = "BSDTableGen",
    )
    return [DefaultInfo(files = depset([out]))]

bsd_tablegen = rule(implementation = _impl, attrs = {
    "src": attr.label(allow_single_file = [".td"], mandatory = True),
    "includes": attr.label_list(allow_files = [".td"]),
    "include_dirs": attr.string_list(),
    "flags": attr.string_list(),
    "output": attr.string(mandatory = True),
    "tool": attr.label(executable = True, cfg = "exec", mandatory = True),
})
