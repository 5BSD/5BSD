# SPDX-License-Identifier: BSD-2-Clause
"""Declared lexer/parser generation, including flex's m4 subprocess."""

def _generate(ctx):
    flags = ctx.attr.flags
    if any([flag in ["-v", "-b", "-o", "-t"] or flag.startswith("--header-file") for flag in flags]):
        fail("generator flag requires additional output/command modeling")
    outputs = [ctx.outputs.output]
    env = {"LC_ALL": "C"}
    tools = [ctx.executable.generator] + ctx.files.runtime
    args = ctx.actions.args()
    args.add_all(flags)
    if ctx.attr.kind == "lex":
        if ctx.outputs.header or not ctx.executable.m4:
            fail("lexer requires declared m4 and no unmodeled header output")
        env["M4"] = ctx.executable.m4.path
        tools.append(ctx.executable.m4)
        args.add("-o" + ctx.outputs.output.path)
    else:
        if ("-d" in flags) != bool(ctx.outputs.header):
            fail("parser header inventory differs from configured -d flag")
        if ctx.outputs.header:
            if ctx.outputs.header.path != ctx.outputs.output.path[:-2] + ".h":
                fail("named parser header must share the C output stem")
            outputs.append(ctx.outputs.header)
        args.add("-o")
        args.add(ctx.outputs.output)
    args.add(ctx.file.source)
    ctx.actions.run(
        executable = ctx.executable.generator,
        arguments = [args],
        inputs = [ctx.file.source] + ctx.files.dependencies,
        tools = tools,
        outputs = outputs,
        env = env,
        use_default_shell_env = False,
        mnemonic = "BSDLexGenerate" if ctx.attr.kind == "lex" else "BSDYaccGenerate",
    )
    return [DefaultInfo(files = depset(outputs))]

bsd_lexyacc = rule(
    implementation = _generate,
    attrs = {
        "kind": attr.string(values = ["lex", "yacc"], mandatory = True),
        "source": attr.label(allow_single_file = [".l", ".y"], mandatory = True),
        "output": attr.output(mandatory = True),
        "header": attr.output(),
        "flags": attr.string_list(),
        "dependencies": attr.label_list(allow_files = True),
        "generator": attr.label(executable = True, cfg = "exec", allow_files = True, mandatory = True),
        "m4": attr.label(executable = True, cfg = "exec", allow_files = True),
        "runtime": attr.label_list(allow_files = True, cfg = "exec"),
    },
)
