# SPDX-License-Identifier: BSD-2-Clause
"""Select the configured optional libc ABI at NIS consumer boundaries.

A program using a NIS-enabled RPC/wrapper DSO must resolve that DSO against
configured libc, rather than the feature-disabled bootstrap SDK libc.
"""

def nis_runtime_deps():
    return select({"//tools/build/bazel/config:nis_enabled": ["//lib/libc:shared_abi_interface"], "//conditions:default": []})

def nis_runtime_linkopts():
    return select({"//tools/build/bazel/config:nis_enabled": ["-nodefaultlibs"], "//conditions:default": []})
