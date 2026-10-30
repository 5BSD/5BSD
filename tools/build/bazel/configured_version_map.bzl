# SPDX-License-Identifier: BSD-2-Clause
"""Configured BSD symbol-map concatenation, preprocessing and AWK generation."""

def _impl(ctx):
    if not ctx.files.symbol_maps:
        fail("ordered symbol maps required")
    combined = ctx.actions.declare_file(ctx.label.name + ".symbols")
    preprocessed = ctx.actions.declare_file(ctx.label.name + ".preprocessed")
    output = ctx.actions.declare_file(ctx.label.name + ".map")
    ctx.actions.run(
        executable = ctx.attr.redirect[DefaultInfo].files_to_run,
        arguments = [combined.path, ctx.executable.cat.path] + [f.path for f in ctx.files.symbol_maps],
        inputs = ctx.files.symbol_maps,
        tools = [ctx.attr.cat[DefaultInfo].files_to_run] + ctx.files.cat_runtime,
        outputs = [combined], env = {"LC_ALL": "C"}, use_default_shell_env = False,
        mnemonic = "BSDVersionConcatenate",
    )
    # Preserve the maintained pipe's stdin semantics, including quoted includes
    # and preprocessor line markers; do not preprocess each map independently.
    ctx.actions.run(
        executable = ctx.attr.redirect[DefaultInfo].files_to_run,
        arguments = ["--stdin", combined.path, preprocessed.path, ctx.executable.compiler.path,
                     "--driver-mode=cpp"] + [ctx.expand_make_variables("copts", flag, {}) for flag in ctx.attr.cpp_flags + ctx.attr.copts] + ["-", "-"],
        inputs = depset([combined] + ctx.files.headers,
                        transitive = [ctx.attr.compiler_inputs[DefaultInfo].files]),
        tools = [ctx.attr.compiler[DefaultInfo].files_to_run],
        outputs = [preprocessed], env = {"LC_ALL": "C"}, use_default_shell_env = False,
        mnemonic = "BSDVersionPreprocess",
    )
    ctx.actions.run(
        executable = ctx.attr.redirect[DefaultInfo].files_to_run,
        arguments = [output.path, ctx.executable.awk.path, "-v", "vfile=" + ctx.file.versions.path,
                     "-f", ctx.file.generator.path, preprocessed.path],
        inputs = [preprocessed, ctx.file.versions, ctx.file.generator],
        tools = [ctx.attr.awk[DefaultInfo].files_to_run] + ctx.files.awk_runtime,
        outputs = [output], env = {"LC_ALL": "C"}, use_default_shell_env = False,
        mnemonic = "BSDVersionGenerate",
    )
    return [DefaultInfo(files = depset([output]))]

bsd_configured_version_map = rule(
    implementation = _impl,
    attrs = {
        "symbol_maps": attr.label_list(allow_files = True, mandatory = True),
        "versions": attr.label(allow_single_file = True, mandatory = True),
        "generator": attr.label(allow_single_file = True, mandatory = True),
        "headers": attr.label_list(allow_files = True),
        "cpp_flags": attr.string_list(mandatory = True),
        "copts": attr.string_list(),
        "compiler": attr.label(allow_single_file = True, executable = True, cfg = "exec", mandatory = True),
        "compiler_inputs": attr.label(mandatory = True),
        "cat": attr.label(allow_single_file = True, executable = True, cfg = "exec", mandatory = True),
        "cat_runtime": attr.label(cfg = "exec", mandatory = True),
        "awk": attr.label(allow_single_file = True, executable = True, cfg = "exec", mandatory = True),
        "awk_runtime": attr.label(cfg = "exec", mandatory = True),
        "redirect": attr.label(executable = True, cfg = "exec", mandatory = True),
    },
)
