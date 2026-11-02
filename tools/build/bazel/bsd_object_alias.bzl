# SPDX-License-Identifier: BSD-2-Clause
"""Give a compiled object its declared final-link filename without rewriting it."""
def _alias(ctx):
    ctx.actions.symlink(output = ctx.outputs.output, target_file = ctx.file.src)
    return [DefaultInfo(files = depset([ctx.outputs.output]))]

bsd_object_alias = rule(implementation = _alias, attrs = {
    "src": attr.label(allow_single_file = [".o", ".pico"], mandatory = True),
    "output": attr.output(mandatory = True),
})
