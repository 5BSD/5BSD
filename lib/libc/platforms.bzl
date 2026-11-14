# SPDX-License-Identifier: BSD-2-Clause
"""Target CPU support for libc's portable source groups.

Architecture-owned implementations retain their own explicit constraints.
"""
LIBC_PORTABLE_PLATFORMS = ["@platforms//os:freebsd"] + select({
    "@platforms//cpu:x86_64": [],
    "@platforms//cpu:aarch64": [],
    "//conditions:default": ["@platforms//:incompatible"],
})
