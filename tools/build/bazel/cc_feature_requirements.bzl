# SPDX-License-Identifier: BSD-2-Clause
"""Reject toolchains that silently ignore component-required optional features."""
load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain", "use_cc_toolchain")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")
def _impl(ctx):
    toolchain = find_cc_toolchain(ctx)
    features = cc_common.configure_features(ctx = ctx, cc_toolchain = toolchain,
        requested_features = ctx.features + ctx.attr.required_features,
        unsupported_features = ctx.disabled_features)
    for feature in ctx.attr.required_features:
        if not cc_common.is_enabled(feature_configuration = features, feature_name = feature):
            fail("selected SDK lacks required component feature: " + feature)
    return [CcInfo()]
bsd_cc_feature_requirements = rule(implementation = _impl,
    attrs = {"required_features": attr.string_list(mandatory = True)},
    toolchains = use_cc_toolchain(), fragments = ["cpp"], provides = [CcInfo])
