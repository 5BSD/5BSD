# SPDX-License-Identifier: BSD-2-Clause
"""Embed unsigned policy inputs; final-image signing remains a separate step."""

def _policy_assembly(ctx):
    output = ctx.actions.declare_file(ctx.label.name + ".S")
    ctx.actions.run(
        executable = ctx.attr._encoder[DefaultInfo].files_to_run,
        arguments = [ctx.file.src.path, output.path],
        inputs = [ctx.file.src],
        outputs = [output],
        mnemonic = "BSDCapimagePolicy",
        use_default_shell_env = False,
    )
    return [DefaultInfo(files = depset([output]))]

bsd_capimage_policy = rule(
    implementation = _policy_assembly,
    attrs = {
        "src": attr.label(allow_single_file = True, mandatory = True),
        "_encoder": attr.label(
            default = Label("//tools/build/bazel:capimage_asm"),
            executable = True,
            cfg = "exec",
        ),
    },
)
