# SPDX-License-Identifier: BSD-2-Clause
"""Run the original gen-pc.sh and its original header-version sed expression."""

def _pkgconfig(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add("-c")
    args.add('set -eu\nversion=$("$1" -n "$2" "$3")\nshift 3\nexec "$@" "$version"\n')
    args.add("bzip2-pc")
    args.add(ctx.executable.sed)
    args.add("/bzip2\\/libbzip2 version /{s/.*version //;s/ of.*//p;q;}")
    args.add(ctx.file.header)
    args.add(ctx.executable.shell)
    args.add(ctx.file._script)
    args.add(ctx.file.template)
    args.add(output)
    args.add(ctx.executable.sed)
    args.add(ctx.executable.mv)
    args.add(ctx.executable.rm)
    for name in ["prefix", "exec_prefix", "libdir", "sharedlibdir", "includedir"]:
        args.add(getattr(ctx.attr, name))
    ctx.actions.run(
        executable = ctx.attr.shell[DefaultInfo].files_to_run,
        arguments = [args],
        inputs = [ctx.file.template, ctx.file.header, ctx.file._script],
        tools = [tool[DefaultInfo].files_to_run for tool in [ctx.attr.sed, ctx.attr.mv, ctx.attr.rm]] + ctx.files.runtime,
        outputs = [output],
        env = {"LC_ALL": "C"},
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
        "shell": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "sed": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "mv": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "rm": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "runtime": attr.label_list(cfg = "exec", allow_files = True),
        "_script": attr.label(default = Label(":gen-pc.sh"), allow_single_file = True, cfg = "exec"),
    },
)
