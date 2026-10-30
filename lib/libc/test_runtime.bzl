# SPDX-License-Identifier: BSD-2-Clause
"""Explicit native runtime for libc ATF programs; the supervisor is static."""
LIBC_TEST_RUNTIME = ["//lib/atf/libatf-c:atf_c_shared", "//lib/libc:c_shared", "//lib/libsys:sys_shared"]
