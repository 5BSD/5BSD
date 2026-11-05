# SPDX-License-Identifier: BSD-2-Clause
"""Shared libc test C warning policy; suites own sources, definitions and libraries."""
_WARN_BEGIN = ["-Wsystem-headers", "-Werror", "-Wall", "-Wno-format-y2k"]
_WARN4 = ["-W", "-Wno-unused-parameter", "-Wstrict-prototypes", "-Wmissing-prototypes",
    "-Wpointer-arith", "-Wreturn-type", "-Wcast-qual", "-Wwrite-strings", "-Wswitch",
    "-Wshadow", "-Wunused-parameter", "-Wcast-align"]
_WARN_END = ["-Wno-uninitialized", "-Wno-pointer-sign", "-Wdate-time", "-Wno-empty-body",
    "-Wno-string-plus-int", "-Wno-unused-const-variable",
    "-Wno-error=unused-but-set-parameter", "-Wno-error=cast-function-type-mismatch"]
_WARN2 = ["-Wno-tautological-compare", "-Wno-unused-value", "-Wno-parentheses-equality",
    "-Wno-unused-function", "-Wno-enum-conversion", "-Wno-unused-local-typedef",
    "-Wno-address-of-packed-member", "-Wno-switch", "-Wno-switch-enum", "-Wno-knr-promoted-parameter"]

def libc_test_copts(warnings = 2):
    if warnings not in [2, 4]:
        fail("unsupported libc test warning policy")
    return ["-pipe", "-fno-common", "-fPIE", "-std=gnu17", "-Wno-format-zero-length"] + _WARN_BEGIN + (_WARN4 if warnings == 4 else []) + _WARN_END + (_WARN2 if warnings == 2 else []) + ["-Qunused-arguments"]
