# SPDX-License-Identifier: BSD-2-Clause
"""Native amd64 libc object selection; static/shared ABI variants stay separate."""
COMMON_GROUPS = [
    "//lib/libc/amd64/gen:objects",
    "//lib/libc/capability:objects",
    "//lib/libc/compat-43:objects",
    "//lib/libc/csu:objects",
    "//lib/libc/db:db_objects",
    "//lib/libc/gdtoa:gdtoa_objects",
    "//lib/libc/gdtoa:netlib_objects",
    "//lib/libc/gen:directory_objects",
    "//lib/libc/gen:directory_blocks_objects",
    "//lib/libc/gen:process_objects",
    "//lib/libc/gen:random_objects",
    "//lib/libc/gen:system_helper_objects",
    "//lib/libc/gen:support_objects",
    "//lib/libc/gen:loader_import_objects",
    "//lib/libc/gen:account_objects",
    "//lib/libc/gmon:objects",
    "//lib/libc/inet:inet_objects",
    "//lib/libc/isc:isc_objects",
    "//lib/libc/locale:locale_objects",
    "//lib/libc/nameser:nameser_objects",
    "//lib/libc/nls:msgcat_objects",
    "//lib/libc/posix1e:posix1e_objects",
    "//lib/libc/regex:regex_objects",
    "//lib/libc/rpc:rpc_objects",
    "//lib/libc/secure:objects",
    "//lib/libc/secure:format_objects",
    "//lib/libc/secure:stack_protector_objects",
    "//lib/libc/stdbit:objects",
    "//lib/libc/stdio:stdio_objects",
    "//lib/libc/stdlib:stdlib_objects",
    "//lib/libc/stdlib:qsort_objects",
    "//lib/libc/stdlib:division_objects",
    "//lib/libc/stdlib/malloc:sized_free_objects",
    "//lib/libc/stdlib/malloc/jemalloc:jemalloc_objects",
    "//lib/libc/stdtime:time_objects",
    "//lib/libc/stdtime:localtime_objects",
    "//lib/libc/stdtime:time32_objects",
    "//lib/libc/string:string_objects",
    "//lib/libc/string:page_read_objects",
    "//lib/libc/sys:interposed_objects",
    "//lib/libc/sys:pseudo_objects",
    "//lib/libc/sys:common_libsys_objects",
    "//lib/libc/sys:x86_objects",
    "//lib/libc/sys:vdso_gettc_objects",
    "//lib/libc/uuid:uuid_objects",
    "//lib/libc/x86/gen:objects",
    "//lib/libc/xdr:xdr_objects",
    "//lib/libc/net:lexer_objects",
] + select({
    "//tools/build/bazel/config:iconv_enabled": ["//lib/libc/iconv:iconv_objects"], "//conditions:default": [],
}) + select({
    "//tools/build/bazel/config:nis_enabled": ["//lib/libc/yp:yp_objects"], "//conditions:default": [],
}) + select({
    "//tools/build/bazel/config:machdep_optimizations_enabled": ["//lib/libc/string:archlevel_objects"], "//conditions:default": [],
})
TRACE_GROUPS = ["//lib/libc/net:net_objects", "//lib/libc/resolv:resolv_objects", "//lib/libc/gen:semaphore_objects"]
STATIC_GROUPS = ["//lib/libc/sys:static_libsys_objects", "//lib/libc/sys:amd64_objects", "//lib/libc/sys:syscall_objects"] + select({
    "//tools/build/bazel/config:iconv_enabled": ["//lib/libc/iconv:static_wrapper_objects"], "//conditions:default": [],
})
SHARED_GROUPS = ["//lib/libc/sys:shared_libsys_objects", "//lib/libc/sys:amd64_shared_objects", "//lib/libc/sys:shared_syscall_objects"]

# NOSSP derives from Make OBJS with shared compilation flags, without the
# SOBJS-only libc_stubs or STATICOBJS-only implementations/wrappers.
NOSSP_GROUPS = ["//lib/libc/sys:amd64_shared_objects", "//lib/libc/sys:shared_syscall_objects"]
