# SPDX-License-Identifier: BSD-2-Clause
"""A native target that cannot be built yet and says why.

Analysis of the target, or of anything that depends on it, fails with the
given reason instead of silently producing an artifact that no longer matches
the Make build.  The rule claims CcInfo so it can stand where a cc_library
was; it never returns.
"""
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")

def _impl(ctx):
    fail("%s is not buildable by the native Bazel graph: %s" %
         (ctx.label, ctx.attr.reason))

bsd_unavailable = rule(
    implementation = _impl,
    attrs = {"reason": attr.string(mandatory = True)},
    provides = [CcInfo],
)
