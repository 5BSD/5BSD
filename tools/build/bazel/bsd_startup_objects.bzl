# SPDX-License-Identifier: BSD-2-Clause
"""Expose native startup objects to ordinary rules_cc compiler-driver links."""
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")

def _impl(ctx):
    objects = ctx.files.objects
    directories = depset([f.dirname for f in objects]).to_list()
    names = [f.basename for f in objects]
    if len(directories) != 1 or len(names) != len(depset(names).to_list()):
        fail("startup objects require unique names in one declared directory")
    missing = [name for name in ctx.attr.required_names if name not in names]
    if missing:
        fail("missing startup objects: " + str(missing))
    link = cc_common.create_linker_input(owner = ctx.label,
        user_link_flags = depset(["-B" + directories[0] + "/"]),
        additional_inputs = depset(objects))
    return [DefaultInfo(files = depset(objects)),
        CcInfo(linking_context = cc_common.create_linking_context(linker_inputs = depset([link])))]

bsd_startup_objects = rule(implementation = _impl, attrs = {
    "objects": attr.label(allow_files = [".o"], mandatory = True),
    "required_names": attr.string_list(mandatory = True),
})
