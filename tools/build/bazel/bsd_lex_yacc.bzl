# SPDX-License-Identifier: BSD-2-Clause
"""Declared lexer/parser actions using staged bootstrap tools."""
def _lex(ctx):
    out = ctx.actions.declare_file(ctx.attr.output)
    if any([flag.startswith("--header-file") for flag in ctx.attr.flags]):
        fail("use header to declare the generated lexer header")
    header = ctx.actions.declare_file(ctx.attr.header) if ctx.attr.header else None
    headers = [header] if header else []
    ctx.actions.run(executable = ctx.executable.lex,
        arguments = ctx.attr.flags + (["--header-file=" + header.path] if header else []) + ["-o" + out.path, ctx.file.src.path],
        inputs = [ctx.file.src], tools = [ctx.attr.m4[DefaultInfo].files_to_run] + ctx.files.runtime,
        outputs = [out] + headers, env = {"LC_ALL": "C", "M4": ctx.executable.m4.path},
        use_default_shell_env = False, mnemonic = "BSDLex")
    return [DefaultInfo(files = depset([out] + headers)),
        OutputGroupInfo(source = depset([out]), header = depset(headers))]

def _yacc(ctx):
    source = ctx.actions.declare_file(ctx.attr.output)
    header = ctx.actions.declare_file(ctx.attr.header) if ctx.attr.header else None
    headers = [header] if header else []
    report = ctx.actions.declare_file(ctx.attr.report) if ctx.attr.report else None
    if "-v" in ctx.attr.flags:
        fail("use report to declare yacc's verbose output")
    # byacc removes .tab.c before falling back to .c when deriving its prefix.
    report_stem = source.path[:-6] if source.path.endswith(".tab.c") else source.path[:-2]
    if report and (not source.path.endswith(".c") or report.path != report_stem + ".output"):
        fail("yacc report must match the generator-derived output stem")
    reports = [report] if report else []
    arguments = ctx.attr.flags + (["-v"] if report else []) + (["-d"] if header else []) + ["-o", source.path]
    if header:
        arguments += ["-H", header.path]
    arguments.append(ctx.file.src.path)
    ctx.actions.run(executable = ctx.executable.yacc,
        arguments = arguments,
        inputs = [ctx.file.src], tools = ctx.files.runtime, outputs = [source] + headers + reports,
        env = {"LC_ALL": "C"}, use_default_shell_env = False, mnemonic = "BSDYacc")
    return [DefaultInfo(files = depset([source] + headers + reports)),
        OutputGroupInfo(source = depset([source]), header = depset(headers), report = depset(reports))]

bsd_lex = rule(implementation = _lex, attrs = {
    "src": attr.label(allow_single_file = [".l"], mandatory = True),
    "output": attr.string(mandatory = True), "header": attr.string(), "flags": attr.string_list(),
    "lex": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "m4": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
})
bsd_yacc = rule(implementation = _yacc, attrs = {
    "src": attr.label(allow_single_file = [".y"], mandatory = True),
    "output": attr.string(mandatory = True), "header": attr.string(), "report": attr.string(), "flags": attr.string_list(),
    "yacc": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
})
