# SPDX-License-Identifier: BSD-2-Clause
"""RPC generation with explicit generator, preprocessor and include inputs."""

def _quote(value):
    # rpcgen parses RPCGEN_CPP itself using shell-style word quoting; it does
    # not invoke a shell. Quote every argument without evaluating its contents.
    return "'" + value.replace("'", "'\\''") + "'"

def _generate(ctx):
    cpp = [ctx.executable.cpp.path] + ctx.attr.cpp_flags
    args = ctx.actions.args()
    if ctx.attr.output_to_stdout:
        args.add(ctx.outputs.output)
        args.add(ctx.executable.rpcgen)
    args.add_all(ctx.attr.flags)
    args.add(ctx.attr.mode)
    if not ctx.attr.output_to_stdout:
        args.add("-o")
        args.add(ctx.outputs.output)
    args.add(ctx.file.source)
    ctx.actions.run(
        executable = ctx.executable.redirect if ctx.attr.output_to_stdout else ctx.executable.rpcgen,
        arguments = [args],
        inputs = depset([ctx.file.source] + ctx.files.dependencies,
                        transitive = [ctx.attr.compiler_inputs[DefaultInfo].files]),
        tools = [ctx.attr.rpcgen[DefaultInfo].files_to_run, ctx.attr.cpp[DefaultInfo].files_to_run] + ctx.files.runtime,
        outputs = [ctx.outputs.output],
        env = {"LC_ALL": "C", "RPCGEN_CPP": " ".join([_quote(v) for v in cpp])},
        use_default_shell_env = False,
        mnemonic = "BSDRpcGenerate",
    )
    return [DefaultInfo(files = depset([ctx.outputs.output]))]

bsd_rpcgen = rule(
    implementation = _generate,
    attrs = {
        "source": attr.label(allow_single_file = [".x"], mandatory = True),
        "output": attr.output(mandatory = True),
        "mode": attr.string(values = ["-h", "-l", "-c", "-m"], mandatory = True),
        "flags": attr.string_list(),
        # rpcgen derives header guards from -o; stdout preserves the schema name.
        "output_to_stdout": attr.bool(default = False),
        "redirect": attr.label(executable = True, cfg = "exec", allow_single_file = True,
            default = "@bsd_sdk//toolchain:stdout_redirect"),
        "cpp_flags": attr.string_list(),
        "dependencies": attr.label_list(allow_files = True),
        "rpcgen": attr.label(executable = True, cfg = "exec", allow_files = True, mandatory = True),
        "cpp": attr.label(executable = True, cfg = "exec", allow_files = True, mandatory = True),
        "compiler_inputs": attr.label(mandatory = True),
        "runtime": attr.label_list(allow_files = True, cfg = "exec"),
    },
)
