# SPDX-License-Identifier: BSD-2-Clause
"""Decode source payloads with native bintrans and a declared execution runtime."""

def _decode(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add_all([ctx.executable.decoder.path, "uudecode", "-o", output.path, ctx.file.src.path])
    ctx.actions.run(
        executable = ctx.attr.loader[DefaultInfo].files_to_run,
        arguments = [args],
        inputs = [ctx.file.src],
        tools = [ctx.attr.decoder[DefaultInfo].files_to_run] + ctx.files.runtime_libraries,
        outputs = [output],
        env = {"LC_ALL": "C", "LD_LIBRARY_PATH": ":".join(depset([f.dirname for f in ctx.files.runtime_libraries]).to_list())},
        use_default_shell_env = False,
        mnemonic = "BSDNativeUUDecode",
    )
    return [DefaultInfo(files = depset([output]))]

bsd_uudecode = rule(implementation = _decode, attrs = {
    "src": attr.label(allow_single_file = True, mandatory = True),
    "output": attr.string(mandatory = True),
    "decoder": attr.label(executable = True, cfg = "exec", mandatory = True),
    "loader": attr.label(executable = True, cfg = "exec", mandatory = True),
    "runtime_libraries": attr.label_list(allow_files = True, cfg = "exec", mandatory = True),
})
