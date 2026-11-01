# SPDX-License-Identifier: BSD-2-Clause
"""GENERIC module consumers of the maintained CDDL/OpenZFS compatibility API."""
load(":amd64_generic_module.bzl", "amd64_generic_module_objects")
load(":cross_generic_module.bzl", "cross_generic_module_objects")

_COMPATIBILITY_HEADERS = [
    "//sys/contrib/openzfs:tracing_module_headers",
    "//sys/cddl/compat/opensolaris:tracing_module_headers",
    "//sys/cddl/contrib/opensolaris:tracing_module_headers",
]
_FORCED_HEADERS = [
    "//sys/contrib/openzfs:include/os/freebsd/spl/sys/ccompile.h",
    "//sys/cddl/compat/opensolaris:sys/debug_compat.h",
]
_FLAGS = ["-D_SYS_VMEM_H_", "-D__KERNEL__", "-DSMP"] + [
    flag for header in _FORCED_HEADERS[1:] for flag in ["-include", "$(execpath " + header + ")"]
]

# Source-only compatibility contexts preserve used Make include-root order.
# No selected source consumes the additional os/freebsd/zfs search root.
def amd64_cddl_module_objects(srcs, deps, name = "generic_module", header_overrides = [], leading_headers = [], copts = [], textual_hdrs = []):
    amd64_generic_module_objects(name = name, srcs = srcs, deps = deps,
        header_overrides = leading_headers + _COMPATIBILITY_HEADERS + header_overrides,
        preinclude_headers = _FORCED_HEADERS[:1], textual_hdrs = _FORCED_HEADERS[1:] + textual_hdrs, copts = _FLAGS + copts)

def cross_cddl_module_objects(arch, srcs, deps, name = "generic_module", header_overrides = [], leading_headers = [], copts = [], textual_hdrs = []):
    cross_generic_module_objects(arch = arch, name = name, srcs = srcs, deps = deps,
        header_overrides = leading_headers + _COMPATIBILITY_HEADERS + header_overrides,
        preinclude_headers = _FORCED_HEADERS[:1], textual_hdrs = _FORCED_HEADERS[1:] + textual_hdrs, copts = _FLAGS + copts)
