# SPDX-License-Identifier: BSD-2-Clause
"""Declare startup artifacts and response flags for rules_cc final links."""

def _impl(ctx):
    objects = ctx.files.objects
    directories = depset([f.dirname for f in objects]).to_list()
    names = [f.basename for f in objects]
    if len(directories) != 1 or len(names) != len(depset(names).to_list()):
        fail("startup objects require unique names in one declared directory")
    missing = [name for name in ctx.attr.required_names if name not in names]
    if missing:
        fail("missing startup objects: " + str(missing))
    flags = ctx.actions.declare_file(ctx.label.name + ".params")
    ctx.actions.write(flags, "-B" + directories[0] + "/\n")
    # Final link attributes consume this response file and the object inputs.
    # CcInfo flags alone can be pruned during dynamic_deps processing.
    return [DefaultInfo(files = depset(objects)), OutputGroupInfo(link_flags = depset([flags]))]

bsd_startup_objects = rule(implementation = _impl, attrs = {
    "objects": attr.label(allow_files = [".o"], mandatory = True),
    "required_names": attr.string_list(mandatory = True),
})
