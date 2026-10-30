# SPDX-License-Identifier: BSD-2-Clause
"""C/C++ rule symbols for the probes' WORKSPACE mode (Bazel 5).

The probes stage this file, or cc_compat_bzlmod.bzl for Bazel 9 with
Bzlmod and rules_cc, as //toolchain:cc_compat.bzl.  Starlark files and
BUILD overlays load every C/C++ symbol through it under the bsd_ names, so
one set of files serves both modes.  Here the symbols are Bazel's native
ones and the toolchain comes from --crosstool_top (no toolchain type).
"""

load("@bazel_tools//tools/cpp:cc_toolchain_config_lib.bzl", "feature", "flag_group", "flag_set", "tool_path")
load("@bazel_tools//tools/cpp:toolchain_utils.bzl", "find_cpp_toolchain")

BSD_CC_MODE = "workspace"
bsd_cc_common = cc_common
bsd_CcInfo = CcInfo
bsd_CcToolchainConfigInfo = CcToolchainConfigInfo
bsd_feature = feature
bsd_flag_group = flag_group
bsd_flag_set = flag_set
bsd_tool_path = tool_path
bsd_find_cc_toolchain = find_cpp_toolchain
BSD_CC_TOOLCHAIN_ATTRS = {
    "_cc_toolchain": attr.label(default = Label("@bazel_tools//tools/cpp:current_cc_toolchain")),
}
BSD_CC_TOOLCHAINS = []

def bsd_cc_library(**kwargs):
    native.cc_library(**kwargs)

def bsd_cc_binary(**kwargs):
    native.cc_binary(**kwargs)
