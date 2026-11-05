# SPDX-License-Identifier: BSD-2-Clause
"""Select the configured optional libc ABI at NIS consumer boundaries.

A program using a NIS-enabled RPC/wrapper DSO must resolve that DSO against
configured libc, rather than the feature-disabled bootstrap SDK libc.
"""

def nis_runtime_deps():
    return select({"//tools/build/bazel/config:nis_enabled": ["//lib/libc:shared_abi_interface"], "//conditions:default": []})

def nis_runtime_linkopts():
    return select({"//tools/build/bazel/config:nis_enabled": ["-nodefaultlibs"], "//conditions:default": []})

def nis_runtime_libraries():
    """Declared test DSOs matching the selected optional consumer ABI.

    NIS consumers use source-built libc; default consumers retain the explicit
    bootstrap ABI already used by their program links and existing tests.
    """
    return select({
        "//tools/build/bazel/config:nis_enabled": ["//lib/libc:c_shared", "//lib/libsys:sys_shared"],
        "//conditions:default": ["@bsd_sdk//toolchain:sysroot/lib/libc.so.7", "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7"],
    })
