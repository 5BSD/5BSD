# SPDX-License-Identifier: BSD-2-Clause
"""Generate a file with a declared awk program, data and execution tools."""

load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")

def _generate(ctx):
    if ctx.files.srcs and ctx.attr.stdin_text:
        fail("select file inputs or stdin_text, not both")
    output = ctx.actions.declare_file(ctx.attr.output)
    stdin = ctx.actions.declare_file(ctx.label.name + ".stdin")
    ctx.actions.write(stdin, ctx.attr.stdin_text)
    args = ctx.actions.args()
    args.add_all(["--stdin", stdin.path, output.path, ctx.executable.awk.path, "-f", ctx.file.script.path])
    for name, value in sorted(ctx.attr.variables.items()):
        if not name or name[0] in "0123456789" or any([c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for c in name.elems()]):
            fail("invalid awk variable name: " + name)
        args.add(name + "=" + value)
    operands = list(ctx.attr.arguments)
    if ctx.attr.arguments_setting:
        value = ctx.attr.arguments_setting[BuildSettingInfo].value
        if type(value) != "string":
            fail("awk argument setting must be a space-separated string")
        operands += [word for word in value.split(" ") if word]
    if ctx.attr.end_of_options or operands or ctx.attr.arguments_setting:
        args.add("--")
    args.add_all(operands)
    args.add_all(ctx.files.srcs)
    ctx.actions.run(
        executable = ctx.executable.redirect,
        arguments = [args],
        inputs = [ctx.file.script, stdin] + ctx.files.srcs + ctx.files.runtime,
        tools = [ctx.attr.awk[DefaultInfo].files_to_run],
        outputs = [output],
        env = {"LC_ALL": "C"},
        use_default_shell_env = False,
        mnemonic = "BsdAwkOutput",
    )
    return [DefaultInfo(files = depset([output]))]

bsd_awk_output = rule(implementation = _generate, attrs = {
    "script": attr.label(allow_single_file = True, mandatory = True),
    "srcs": attr.label_list(allow_files = True),
    "stdin_text": attr.string(),
    "variables": attr.string_dict(),
    "arguments": attr.string_list(doc = "Explicit operands after --, before input files."),
    "arguments_setting": attr.label(providers = [BuildSettingInfo], doc = "Optional space-separated operand string; no shell expansion."),
    "end_of_options": attr.bool(default = False, doc = "Emit -- even without operands, for BEGIN-only generators."),
    "output": attr.string(mandatory = True),
    "awk": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "redirect": attr.label(executable = True, cfg = "exec", mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
})
