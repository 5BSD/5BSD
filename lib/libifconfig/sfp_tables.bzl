# SPDX-License-Identifier: BSD-2-Clause
"""Render the maintained SFP templates with explicit Lua inputs."""
def _render(ctx):
    outputs = []
    # sfp.lua locates tools/lua/template.lua relative to SRCTOP.
    suffix = "/tools/lua/template.lua"
    module_path = ctx.file.template_module.path
    root = module_path[:-len(suffix)] if module_path.endswith(suffix) else "."
    if module_path != "tools/lua/template.lua" and not module_path.endswith(suffix):
        fail("template module must retain its source-relative tools/lua path")
    for template in ctx.files.templates:
        output = ctx.actions.declare_file(template.basename.replace(".tpl.", "."))
        ctx.actions.run(
            executable = ctx.attr.redirect[DefaultInfo].files_to_run,
            arguments = [output.path, ctx.executable.lua.path, ctx.file.generator.path, template.path],
            inputs = [template, ctx.file.generator, ctx.file.template_module],
            tools = [ctx.attr.lua[DefaultInfo].files_to_run] + ctx.files.runtime,
            outputs = [output],
            env = {"SRCTOP": root, "LC_ALL": "C"},
            use_default_shell_env = False,
            mnemonic = "BSDSfpTable",
        )
        outputs.append(output)
    return [
        DefaultInfo(files = depset(outputs)),
        OutputGroupInfo(headers = depset([f for f in outputs if f.extension == "h"]),
                        sources = depset([f for f in outputs if f.extension == "c"])),
    ]

sfp_tables = rule(
    implementation = _render,
    attrs = {
        "templates": attr.label_list(allow_files = True, mandatory = True),
        "generator": attr.label(allow_single_file = True, mandatory = True),
        "template_module": attr.label(allow_single_file = True, mandatory = True),
        "lua": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "redirect": attr.label(executable = True, cfg = "exec", mandatory = True),
        "runtime": attr.label_list(allow_files = True, cfg = "exec"),
    },
)
