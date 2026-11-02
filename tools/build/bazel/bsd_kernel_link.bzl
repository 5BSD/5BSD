# SPDX-License-Identifier: BSD-2-Clause
"""Native final kernel link with explicit validated input order and scripts."""
load("//tools/build/bazel:bsd_kernel_inputs.bzl", "KernelLinkInputsInfo")


def _impl(ctx):
    selected = ctx.attr.objects[KernelLinkInputsInfo]
    output = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add_all(["-m", ctx.attr.emulation, "-Bdynamic", "-L", ctx.file.script.dirname,
                  "-T", ctx.file.script.path])
    args.add_all(ctx.attr.linkopts)
    args.add_all(["--no-warn-mismatch", "--warn-common", "--export-dynamic",
                  "--dynamic-linker", "/red/herring", "-X", "-o", output.path])
    args.add_all(selected.objects)
    args.use_param_file("@%s", use_always = True)
    ctx.actions.run(
        executable = ctx.attr.linker[DefaultInfo].files_to_run,
        arguments = [args],
        inputs = selected.objects + [selected.validation, ctx.file.script] + ctx.files.script_inputs,
        tools = ctx.files.linker_inputs,
        outputs = [output], env = {"LC_ALL": "C"},
        use_default_shell_env = False, mnemonic = "BSDKernelLink",
    )
    return [DefaultInfo(files = depset([output]))]


bsd_kernel_link = rule(implementation = _impl, attrs = {
    "objects": attr.label(providers = [KernelLinkInputsInfo], mandatory = True),
    "script": attr.label(allow_single_file = True, mandatory = True),
    "script_inputs": attr.label_list(allow_files = True),
    "emulation": attr.string(mandatory = True),
    "linkopts": attr.string_list(),
    "output": attr.string(mandatory = True),
    "linker": attr.label(executable = True, allow_single_file = True, cfg = "exec", mandatory = True),
    "linker_inputs": attr.label_list(allow_files = True, cfg = "exec"),
})
