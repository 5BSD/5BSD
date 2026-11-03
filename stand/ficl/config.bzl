# SPDX-License-Identifier: BSD-2-Clause
"""Explicit metadata for Ficl's generated softcore source."""
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")

def _datestamp(ctx):
    value = ctx.build_setting_value
    if any([c in value for c in ["\n", "\r", "\000", "*/", "\\"]]):
        fail("Ficl datestamp must be one C comment line without a terminator or AWK escapes")
    return [BuildSettingInfo(value = value)]

ficl_datestamp = rule(implementation = _datestamp, build_setting = config.string(flag = True))
