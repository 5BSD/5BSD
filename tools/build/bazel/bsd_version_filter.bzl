# SPDX-License-Identifier: BSD-2-Clause
"""Native declared version-map filtering with the selected staged sed tool."""

def _filter(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    ctx.actions.run(
        executable = ctx.attr.redirect[DefaultInfo].files_to_run,
        arguments = [output.path, ctx.executable.sed.path] + ctx.attr.arguments + [ctx.file.template.path],
        inputs = [ctx.file.template],
        tools = [ctx.attr.sed[DefaultInfo].files_to_run] + ctx.files.runtime,
        outputs = [output], env = {"LC_ALL": "C"}, use_default_shell_env = False,
        mnemonic = "BSDVersionFilter",
    )
    return [DefaultInfo(files = depset([output]))]

bsd_version_filter = rule(
    implementation = _filter,
    attrs = {
        "template": attr.label(allow_single_file = True, mandatory = True),
        "output": attr.string(mandatory = True),
        "arguments": attr.string_list(mandatory = True),
        "sed": attr.label(executable = True, allow_single_file = True, cfg = "exec", mandatory = True),
        "redirect": attr.label(executable = True, allow_single_file = True, cfg = "exec", mandatory = True),
        "runtime": attr.label_list(allow_files = True, cfg = "exec"),
    },
)
