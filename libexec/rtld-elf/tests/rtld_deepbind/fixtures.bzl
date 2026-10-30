# SPDX-License-Identifier: BSD-2-Clause
"""Declared shared-library alias in the installed-equivalent fixture directory."""
def _alias(ctx):
    ctx.actions.symlink(output = ctx.outputs.out, target_file = ctx.file.src)
    return [DefaultInfo(files = depset([ctx.outputs.out]))]
fixture_alias = rule(implementation = _alias, attrs = {
    "src": attr.label(allow_single_file = True, mandatory = True),
    "out": attr.output(mandatory = True),
})
