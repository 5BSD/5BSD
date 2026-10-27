# SPDX-License-Identifier: BSD-2-Clause
"""Expand declared text templates without a shell or host generator."""

def _template(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    ctx.actions.expand_template(
        template = ctx.file.template,
        output = output,
        substitutions = ctx.attr.substitutions,
        is_executable = False,
    )
    return [DefaultInfo(files = depset([output]))]

bsd_template = rule(
    implementation = _template,
    attrs = {
        "template": attr.label(allow_single_file = True, mandatory = True),
        "output": attr.string(mandatory = True),
        "substitutions": attr.string_dict(mandatory = True),
    },
)
