# SPDX-License-Identifier: BSD-2-Clause
"""Declared BSD artifact transformations; installation metadata is separate."""

BsdDebugInfo = provider(fields = ["binary", "debug", "unstripped"])

def _debug_split(ctx):
    binary = ctx.actions.declare_file(ctx.attr.binary_name)
    debug = ctx.actions.declare_file(ctx.attr.debug_name)
    ctx.actions.run(
        executable = ctx.attr.objcopy[DefaultInfo].files_to_run,
        arguments = ["--only-keep-debug", ctx.file.src.path, debug.path],
        inputs = [ctx.file.src], tools = ctx.files.objcopy_inputs,
        outputs = [debug], env = {"LC_ALL": "C"}, use_default_shell_env = False,
        mnemonic = "BSDExtractDebug",
    )
    ctx.actions.run(
        executable = ctx.attr.objcopy[DefaultInfo].files_to_run,
        arguments = ["--strip-debug", "--add-gnu-debuglink=" + debug.path, ctx.file.src.path, binary.path],
        inputs = [ctx.file.src, debug], tools = ctx.files.objcopy_inputs,
        outputs = [binary], env = {"LC_ALL": "C"}, use_default_shell_env = False,
        mnemonic = "BSDSplitDebug",
    )
    return [DefaultInfo(files = depset([binary])),
            OutputGroupInfo(debug_files = depset([debug])),
            BsdDebugInfo(binary = binary, debug = debug, unstripped = ctx.file.src)]

bsd_debug_split = rule(
    implementation = _debug_split,
    attrs = {
        "src": attr.label(allow_single_file = True, mandatory = True),
        "binary_name": attr.string(mandatory = True),
        "debug_name": attr.string(mandatory = True),
        "objcopy": attr.label(allow_single_file = True, executable = True, cfg = "exec", mandatory = True),
        "objcopy_inputs": attr.label(allow_files = True, cfg = "exec", mandatory = True),
    },
)

def _strip_binary(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    ctx.actions.run(
        executable = ctx.attr.strip[DefaultInfo].files_to_run,
        arguments = ["--keep-section=" + section for section in ctx.attr.keep_sections] + ["-o", output.path, ctx.file.src.path],
        inputs = [ctx.file.src], tools = ctx.files.strip_inputs, outputs = [output],
        env = {"LC_ALL": "C"}, use_default_shell_env = False,
        mnemonic = "BSDStripBinary",
    )
    return [DefaultInfo(files = depset([output]))]

bsd_strip_binary = rule(
    implementation = _strip_binary,
    attrs = {
        "src": attr.label(allow_single_file = True, mandatory = True),
        "output": attr.string(mandatory = True),
        "strip": attr.label(allow_single_file = True, executable = True, cfg = "exec", mandatory = True),
        "strip_inputs": attr.label(allow_files = True, cfg = "exec", mandatory = True),
        "keep_sections": attr.string_list(),
    },
)


def _script_wrapper(ctx):
    output = ctx.actions.declare_file(ctx.label.name)
    prefix = ctx.actions.declare_file(ctx.label.name + ".interpreter")
    ctx.actions.write(prefix, "#! " + ctx.attr.interpreter + "\n")
    ctx.actions.run(
        executable = ctx.attr.redirect[DefaultInfo].files_to_run,
        arguments = ["--executable", output.path, ctx.executable.cat.path, prefix.path, ctx.file.body.path],
        inputs = [prefix, ctx.file.body],
        tools = [ctx.attr.cat[DefaultInfo].files_to_run] + ctx.files.cat_runtime,
        outputs = [output], env = {"LC_ALL": "C"}, use_default_shell_env = False,
        mnemonic = "BSDScriptWrapper",
    )
    return [DefaultInfo(files = depset([output]), executable = output)]

bsd_script_wrapper = rule(
    implementation = _script_wrapper,
    executable = True,
    attrs = {
        "body": attr.label(allow_single_file = True, mandatory = True),
        "interpreter": attr.string(mandatory = True),
        "cat": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "cat_runtime": attr.label_list(cfg = "exec", allow_files = True),
        "redirect": attr.label(executable = True, cfg = "exec", mandatory = True),
    },
)
