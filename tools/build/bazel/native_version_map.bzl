# SPDX-License-Identifier: BSD-2-Clause
"""Declared actions for the existing BSD version_gen.awk protocol."""

def _impl(ctx):
    preprocessed = ctx.actions.declare_file(ctx.label.name + ".preprocessed")
    output = ctx.actions.declare_file(ctx.label.name + ".map")
    ctx.actions.run(
        executable = ctx.executable.compiler,
        arguments = ["--target=" + ctx.attr.target, "--sysroot=toolchain/sysroot",
                     "-E", "-x", "c", "-P", "-nostdinc", "-isystem", "toolchain/sysroot/usr/include",
                     ctx.file.symbols.path, "-o", preprocessed.path],
        inputs = depset([ctx.file.symbols], transitive = [ctx.attr.compiler_inputs[DefaultInfo].files]),
        env = {"LC_ALL": "C"},
        use_default_shell_env = False,
        outputs = [preprocessed],
        mnemonic = "BSDVersionPreprocess",
    )
    ctx.actions.run(
        executable = ctx.executable.redirect,
        arguments = [output.path, ctx.executable.awk.path, "-v", "vfile=" + ctx.file.versions.path,
                     "-f", ctx.file.generator.path, preprocessed.path],
        inputs = [preprocessed, ctx.file.versions, ctx.file.generator],
        tools = [ctx.executable.awk] + ctx.files.awk_runtime,
        env = {"LC_ALL": "C"},
        use_default_shell_env = False,
        outputs = [output],
        mnemonic = "BSDVersionGenerate",
    )
    return [DefaultInfo(files = depset([output]))]

bsd_version_map = rule(
    implementation = _impl,
    attrs = {
        "symbols": attr.label(allow_single_file = True, mandatory = True),
        "versions": attr.label(allow_single_file = True, mandatory = True),
        "generator": attr.label(allow_single_file = True, mandatory = True),
        "compiler": attr.label(allow_single_file = True, executable = True, cfg = "exec", mandatory = True),
        "compiler_inputs": attr.label(mandatory = True),
        "awk": attr.label(allow_single_file = True, executable = True, cfg = "exec", mandatory = True),
        "awk_runtime": attr.label(mandatory = True, cfg = "exec"),
        "redirect": attr.label(executable = True, cfg = "exec", mandatory = True),
        "target": attr.string(mandatory = True),
    },
)
