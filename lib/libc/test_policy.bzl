# SPDX-License-Identifier: BSD-2-Clause
"""Shared libc test C warning policy; suites own sources, definitions and libraries."""
_WARN_BEGIN = ["-Wsystem-headers", "-Werror", "-Wall", "-Wno-format-y2k"]
_WARN4 = ["-W", "-Wno-unused-parameter", "-Wstrict-prototypes", "-Wmissing-prototypes",
    "-Wpointer-arith", "-Wreturn-type", "-Wcast-qual", "-Wwrite-strings", "-Wswitch",
    "-Wshadow", "-Wunused-parameter", "-Wcast-align"]
_WARN_END = ["-Wno-uninitialized", "-Wno-pointer-sign", "-Wdate-time", "-Wno-empty-body",
    "-Wno-string-plus-int", "-Wno-unused-const-variable",
    "-Wno-error=unused-but-set-parameter", "-Wno-error=cast-function-type-mismatch"]
_WARN_LOW = ["-Wno-tautological-compare", "-Wno-unused-value", "-Wno-parentheses-equality",
    "-Wno-unused-function", "-Wno-enum-conversion", "-Wno-unused-local-typedef",
    "-Wno-address-of-packed-member"]
_WARN2 = ["-Wno-switch", "-Wno-switch-enum", "-Wno-knr-promoted-parameter"]
_WARN3 = _WARN4[:5]

def libc_test_copts(warnings = 2):
    if warnings not in [2, 3, 4, 6]:
        fail("unsupported libc test warning policy")
    if warnings == 6:
        return ["-pipe", "-fno-common", "-fPIE", "-std=gnu17", "-Wno-format-zero-length"] + _WARN_BEGIN + _WARN4 + [
            "-Wchar-subscripts", "-Wnested-externs", "-Wold-style-definition",
            "-Wno-pointer-sign", "-Wdate-time", "-Wmissing-variable-declarations", "-Wthread-safety"] + _WARN_END[3:] + ["-Qunused-arguments"]
    return ["-pipe", "-fno-common", "-fPIE", "-std=gnu17", "-Wno-format-zero-length"] + _WARN_BEGIN + (_WARN4 if warnings == 4 else (_WARN3 if warnings == 3 else [])) + _WARN_END + (_WARN_LOW if warnings <= 3 else []) + (_WARN2 if warnings == 2 else []) + ["-Qunused-arguments"]


def libc_test_cxx_copts(warnings = 2, standard = "gnu++17"):
    if standard not in ["gnu++17", "gnu++20", "c++20"]:
        fail("unsupported libc test C++ standard")
    c_only = ["-std=gnu17", "-Wno-pointer-sign", "-Wstrict-prototypes", "-Wmissing-prototypes", "-Wnested-externs", "-Wold-style-definition"]
    return [flag for flag in libc_test_copts(warnings) if flag not in c_only] + [
        "-nostdinc++", "-std=" + standard, "-Wno-c++20-extensions",
        "-Wno-c++23-lambda-attributes", "-Wno-nullability-completeness"]
