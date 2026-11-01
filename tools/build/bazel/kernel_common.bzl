# SPDX-License-Identifier: BSD-2-Clause
"""Shared maintained kernel warnings and typed debug/CTF policy."""
KERNEL_COMMON_WARNING_FLAGS = [
    "-Wall", "-Wstrict-prototypes", "-Wmissing-prototypes", "-Wpointer-arith",
    "-Wcast-qual", "-Wundef", "-Wno-pointer-sign", "-Wmissing-include-dirs",
    "-fdiagnostics-show-option", "-Wno-unknown-pragmas", "-Wswitch",
    "-Wno-error=tautological-compare", "-Wno-error=empty-body",
    "-Wno-error=parentheses-equality", "-Wno-error=unused-function",
    "-Wno-error=pointer-sign", "-Wno-error=shift-negative-value",
    "-Wno-address-of-packed-member", "-Wno-format-zero-length",
]

KERNEL_WARNING_FLAGS = select({
    "//tools/build/bazel/config:werror_enabled": ["-Werror"],
    "//conditions:default": [],
}) + KERNEL_COMMON_WARNING_FLAGS

# kern.mk places WERROR after the common warning vector for built-in objects.
KERNEL_BUILTIN_WARNING_FLAGS = KERNEL_COMMON_WARNING_FLAGS + select({
    "//tools/build/bazel/config:werror_enabled": ["-Werror"],
    "//conditions:default": [],
})

KERNEL_DEBUG_FLAGS = select({
    "//tools/build/bazel/config:kernel_ctf_and_debug_enabled": ["-g", "-gdwarf-4"],
    "//tools/build/bazel/config:kernel_ctf_enabled": ["-g", "-gdwarf-4"],
    "//tools/build/bazel/config:kernel_debug_enabled": ["-g", "-gdwarf-4"],
    "//conditions:default": ["-g0"],
})
