# SPDX-License-Identifier: BSD-2-Clause
"""bzip2 metadata generation; version is read during execution from bzlib.h."""

def _pkgconfig(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add_all(["-B", "-S", ctx.file._generator.path])
    args.add("--template", ctx.file.template)
    args.add("--header", ctx.file.header)
    args.add("--output", output)
    for name in ["prefix", "exec_prefix", "libdir", "sharedlibdir", "includedir"]:
        args.add("--" + name, getattr(ctx.attr, name))
    ctx.actions.run(
        executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = [args],
        inputs = [ctx.file.template, ctx.file.header, ctx.file._generator, ctx.file.python_home],
        tools = ctx.files.runtime,
        outputs = [output],
        env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1", "LC_ALL": "C"},
        use_default_shell_env = False,
        mnemonic = "Bzip2PkgConfig",
    )
    return [DefaultInfo(files = depset([output]))]

bzip2_pkgconfig = rule(
    implementation = _pkgconfig,
    attrs = {
        "template": attr.label(allow_single_file = True, mandatory = True),
        "header": attr.label(allow_single_file = True, mandatory = True),
        "output": attr.string(mandatory = True),
        "prefix": attr.string(mandatory = True),
        "exec_prefix": attr.string(mandatory = True),
        "libdir": attr.string(mandatory = True),
        "sharedlibdir": attr.string(mandatory = True),
        "includedir": attr.string(mandatory = True),
        "python": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "python_home": attr.label(cfg = "exec", allow_single_file = True, mandatory = True),
        "runtime": attr.label_list(cfg = "exec", allow_files = True),
        "_generator": attr.label(default = Label(":gen-pc.py"), allow_single_file = True, cfg = "exec"),
    },
)
