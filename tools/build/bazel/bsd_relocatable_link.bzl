# SPDX-License-Identifier: BSD-2-Clause
"""Link ordered objects and optional archives without a final executable link."""

def _impl(ctx):
    objects = ctx.files.objects
    inputs = objects + ctx.files.archives
    if not objects or len(depset(inputs).to_list()) != len(inputs):
        fail("relocatable link requires nonempty unique object inputs")
    out = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add_all(ctx.attr.linkopts)
    args.add_all(["-r", "-o", out.path])
    args.add_all(inputs)
    environment = {"LC_ALL": "C"}
    if ctx.files.runtime:
        environment["LD_LIBRARY_PATH"] = ":".join(depset([file.dirname for file in ctx.files.runtime]).to_list())
    ctx.actions.run(executable = ctx.attr.linker[DefaultInfo].files_to_run,
        arguments = [args], inputs = inputs, tools = ctx.files.runtime, outputs = [out],
        env = environment, use_default_shell_env = False,
        mnemonic = "BSDRelocatableLink")
    return [DefaultInfo(files = depset([out]))]

bsd_relocatable_link = rule(implementation = _impl, attrs = {
    "objects": attr.label_list(allow_files = [".o"], mandatory = True),
    "archives": attr.label_list(allow_files = [".a"], doc = "Ordered archives after the objects; extraction flags remain explicit in linkopts."),
    "runtime": attr.label_list(allow_files = True, cfg = "exec", doc = "Declared dynamic libraries for the selected linker; empty preserves its existing runfiles."),
    "output": attr.string(mandatory = True),
    "linkopts": attr.string_list(),
    "linker": attr.label(executable = True, allow_files = True, cfg = "exec", mandatory = True),
})
