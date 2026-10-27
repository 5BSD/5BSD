# SPDX-License-Identifier: BSD-2-Clause
"""Pkg-config templates with versions extracted from declared source headers."""
def _impl(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add_all(["-B", "-S", ctx.file._generator.path])
    args.add("--template", ctx.file.template)
    args.add("--header", ctx.file.header)
    args.add("--patterns", json.encode(ctx.attr.version_patterns))
    args.add("--version-field", ctx.attr.version_field)
    args.add("--substitutions", json.encode(ctx.attr.substitutions))
    args.add("--output", output)
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = [args], outputs = [output],
        inputs = [ctx.file.template, ctx.file.header, ctx.file._generator, ctx.file.python_home],
        tools = ctx.files.runtime,
        env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1", "LC_ALL": "C"},
        mnemonic = "BSDPkgConfig", use_default_shell_env = False)
    return [DefaultInfo(files = depset([output]))]

bsd_header_pkgconfig = rule(implementation = _impl, attrs = {
    "template": attr.label(allow_single_file = True, mandatory = True),
    "header": attr.label(allow_single_file = True, mandatory = True),
    "version_patterns": attr.string_list(mandatory = True),
    "version_field": attr.string(default = "VERSION"),
    "substitutions": attr.string_dict(mandatory = True),
    "output": attr.string(mandatory = True),
    "python": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "python_home": attr.label(cfg = "exec", allow_single_file = True, mandatory = True),
    "runtime": attr.label_list(cfg = "exec", allow_files = True),
    "_generator": attr.label(default = Label(":header_pkgconfig.py"), allow_single_file = True, cfg = "exec"),
})
