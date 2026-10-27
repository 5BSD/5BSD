# SPDX-License-Identifier: BSD-2-Clause
"""Generate linker-script artifacts with declared native template expansion."""

def _script(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    ctx.actions.expand_template(
        template = ctx.file.template,
        output = output,
        substitutions = ctx.attr.substitutions,
        is_executable = False,
    )
    return [DefaultInfo(files = depset([output]))]

bsd_link_script = rule(
    implementation = _script,
    attrs = {
        "template": attr.label(allow_single_file = True, mandatory = True),
        "output": attr.string(mandatory = True),
        "substitutions": attr.string_dict(mandatory = True),
    },
)
