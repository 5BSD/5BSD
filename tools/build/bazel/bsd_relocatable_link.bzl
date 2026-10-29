# SPDX-License-Identifier: BSD-2-Clause
"""Combine an ordered set of declared objects without a final executable link."""

def _impl(ctx):
    objects = ctx.files.objects
    if not objects or len(depset(objects).to_list()) != len(objects):
        fail("relocatable link requires nonempty unique object inputs")
    out = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add_all(ctx.attr.linkopts)
    args.add_all(["-r", "-o", out.path])
    args.add_all(objects)
    ctx.actions.run(executable = ctx.attr.linker[DefaultInfo].files_to_run,
        arguments = [args], inputs = objects, outputs = [out],
        env = {"LC_ALL": "C"}, use_default_shell_env = False,
        mnemonic = "BSDRelocatableLink")
    return [DefaultInfo(files = depset([out]))]

bsd_relocatable_link = rule(implementation = _impl, attrs = {
    "objects": attr.label_list(allow_files = [".o"], mandatory = True),
    "output": attr.string(mandatory = True),
    "linkopts": attr.string_list(),
    "linker": attr.label(executable = True, cfg = "exec", mandatory = True),
})
