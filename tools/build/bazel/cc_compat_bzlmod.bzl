# SPDX-License-Identifier: BSD-2-Clause
"""C/C++ rule symbols for the probes' Bzlmod mode (Bazel 9, rules_cc).

Staged as //toolchain:cc_compat.bzl when a probe runs with --bzlmod-inputs.
Bazel 9 has no WORKSPACE and no native C/C++ rules; the symbols come from
the rules_cc module pinned in the probe's MODULE.bazel, and the staged
toolchain is selected by toolchain resolution (registered in MODULE.bazel,
platform //toolchain:native).  See cc_compat.bzl for the WORKSPACE mode.
"""

load("@rules_cc//cc:cc_toolchain_config_lib.bzl", "feature", "flag_group", "flag_set", "tool_path")
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")
load("@rules_cc//cc:find_cc_toolchain.bzl", "CC_TOOLCHAIN_ATTRS", "find_cc_toolchain", "use_cc_toolchain")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")
load("@rules_cc//cc/toolchains:cc_toolchain_config_info.bzl", "CcToolchainConfigInfo")

BSD_CC_MODE = "bzlmod"
bsd_cc_common = cc_common
bsd_CcInfo = CcInfo
bsd_CcToolchainConfigInfo = CcToolchainConfigInfo
bsd_feature = feature
bsd_flag_group = flag_group
bsd_flag_set = flag_set
bsd_tool_path = tool_path
bsd_find_cc_toolchain = find_cc_toolchain
BSD_CC_TOOLCHAIN_ATTRS = CC_TOOLCHAIN_ATTRS
BSD_CC_TOOLCHAINS = use_cc_toolchain()

def bsd_cc_library(**kwargs):
    cc_library(**kwargs)

def bsd_cc_binary(**kwargs):
    cc_binary(**kwargs)
