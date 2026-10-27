# SPDX-License-Identifier: BSD-2-Clause
"""Decode declared uuencoded source data with an explicit execution runtime."""

def _decode(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add_all(["-B", "-S", ctx.file._decoder.path])
    if ctx.attr.gzip:
        args.add("--gzip")
    args.add_all([ctx.file.src, output])
    ctx.actions.run(
        executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = [args],
        inputs = [ctx.file.src, ctx.file._decoder, ctx.file.python_home],
        tools = ctx.files.runtime,
        outputs = [output],
        env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1", "LC_ALL": "C"},
        use_default_shell_env = False,
        mnemonic = "BSDDecodeUU",
    )
    return [DefaultInfo(files = depset([output]))]

bsd_uu_decode = rule(
    implementation = _decode,
    attrs = {
        "src": attr.label(allow_single_file = True, mandatory = True),
        "output": attr.string(mandatory = True),
        "gzip": attr.bool(default = False),
        "python": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "python_home": attr.label(cfg = "exec", allow_single_file = True, mandatory = True),
        "runtime": attr.label_list(cfg = "exec", allow_files = True),
        "_decoder": attr.label(default = Label("//tools/build/bazel:decode_uu.py"), allow_single_file = True, cfg = "exec"),
    },
)

# Existing fixture consumers share the same declared decoder.
bsd_uu_fixture = bsd_uu_decode
