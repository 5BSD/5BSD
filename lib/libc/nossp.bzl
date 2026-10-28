# SPDX-License-Identifier: BSD-2-Clause
"""A separate libc NOSSP configuration, preserving external dependency policy.

Only libc's own cc_library rules consume LIBC_VARIANT_FEATURES. Dependencies
such as drti retain their ordinary compiler policy, matching Make's separately
built objects. Ordinary libc remains stack protected.
"""
LIBC_VARIANT_FEATURES = select({
    "//lib/libc:nossp_enabled": ["-bsd_ssp"],
    "//conditions:default": [],
})

def _nossp(settings, attr):
    return {"//lib/libc:nossp": True}

_nossp_configuration = transition(
    implementation = _nossp,
    inputs = [],
    outputs = ["//lib/libc:nossp"],
)

def _impl(ctx):
    return [DefaultInfo(files = ctx.attr.archive[DefaultInfo].files)]

libc_nossp_archive = rule(
    implementation = _impl,
    cfg = _nossp_configuration,
    attrs = {
        "archive": attr.label(mandatory = True),
        "_allowlist_function_transition": attr.label(default = "@bazel_tools//tools/allowlists/function_transition_allowlist"),
    },
)
