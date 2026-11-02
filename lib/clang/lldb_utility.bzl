# SPDX-License-Identifier: BSD-2-Clause
"""Original shared/PIC LLDB CLI source, dependency and installation policies."""
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")
load("//tools/build/bazel:bsd_llvm_targets.bzl", "bsd_llvm_targets")
load("//tools/build/bazel:bsd_clang_defaults.bzl", "bsd_clang_defaults")
load("//tools/build/bazel:bsd_component_archive.bzl", "bsd_component_sources", "bsd_component_objects")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")

def lldb_utility(name, srcs, options, headers, manual, kvm = False):
    platform = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
    bsd_llvm_targets(name = "registered_targets")
    bsd_clang_defaults(name = "compiler_defaults")
    cc_library(name = "option_headers", hdrs = [options], strip_include_prefix = ".")
    cc_library(name = "objects", srcs = srcs,
        deps = [":option_headers", ":registered_targets", ":compiler_defaults", headers,
                "//contrib/llvm-project/lldb:headers", "//contrib/llvm-project/clang/include:headers",
                "//contrib/llvm-project/llvm/include:headers", "//contrib/llvm-project/libcxx/include:headers",
                "//lib/clang/libllvm:intrinsic_headers", "//lib/clang/libllvm:ir_generated_headers",
                "//lib/clang/libllvm:directive_headers", "//lib/clang/libllvm:target_definition_headers",
                "//usr.bin/clang/llvm-min-tblgen:value_type_headers"],
        copts = ['-pipe', '-fno-common', '-Wno-format-zero-length', '-Wdate-time', '-Wno-empty-body', '-Wno-string-plus-int', '-Wno-unused-const-variable', '-Wno-error=unused-but-set-parameter', '-Wno-error=cast-function-type-mismatch', '-Wno-tautological-compare', '-Wno-unused-value', '-Wno-parentheses-equality', '-Wno-unused-function', '-Wno-enum-conversion', '-Wno-unused-local-typedef', '-Wno-address-of-packed-member', '-Wno-switch', '-Wno-switch-enum', '-Wno-knr-promoted-parameter', '-Wno-parentheses', '-Qunused-arguments', '-Wno-c++20-extensions', '-Wno-c++23-lambda-attributes', '-Wno-nullability-completeness', '-std=c++17', '-nostdinc++', '-fno-exceptions', '-fno-rtti', '-fvisibility-inlines-hidden', '-ffunction-sections', '-fdata-sections', '-fPIE'] + select({"//tools/build/bazel/config:llvm_full_debuginfo_enabled": ["-g"], "//conditions:default": ["-gline-tables-only"]}),
        local_defines = ['__STDC_CONSTANT_MACROS', '__STDC_FORMAT_MACROS', '__STDC_LIMIT_MACROS', 'HAVE_VCS_VERSION_INC'] + select({"//tools/build/bazel/config:llvm_assertions_enabled": [], "//conditions:default": ["NDEBUG"]}) + select({"//tools/build/bazel/config:clang_full_enabled": ["CLANG_ENABLE_STATIC_ANALYZER"], "//conditions:default": []}),
        target_compatible_with = platform)
    libraries = ["//lib/clang/liblldb:lldb", "//lib/clang/libclang:clang", "//lib/clang/libllvm:llvm",
                 "//lib/ncurses/tinfo:tinfo", "//lib/libedit:edit", "//lib/libexecinfo:execinfo"]
    shared = ["//lib/clang/liblldb:lldb_shared", "//lib/clang/libclang:clang_shared", "//lib/clang/libllvm:llvm_shared",
              "//lib/ncurses/tinfo:tinfo_shared", "//lib/libedit:edit_shared", "//lib/libexecinfo:execinfo_shared"]
    if kvm:
        libraries.append("//lib/libkvm:kvm")
        shared.append("//lib/libkvm:kvm_shared")
    libraries += ["//lib/liblua:lua_pie", "//lib/msun:m", "//lib/liblzma:lzma", "//lib/ncurses/ncurses:ncurses", "//lib/ncurses/panel:panel", "//lib/libz:z", "//lib/libzstd:zstd", "//lib/libthr:thr", "//lib/libc++:cxx"]
    shared += ["//lib/msun:m_shared", "//lib/liblzma:lzma_shared", "//lib/ncurses/ncurses:ncurses_shared", "//lib/ncurses/panel:panel_shared", "//lib/libz:z_shared", "//lib/libzstd:zstd_shared", "//lib/libthr:thr_shared", "//lib/libc++:cxx_shared", "//lib/libcxxrt:cxxrt_shared"]
    for variant, runtime in [(name, True), (name + "_installed", False)]:
        cc_binary(name = variant, srcs = [":compiler_outputs"], deps = libraries + (["//lib/libc:shared_link_interface"] if runtime else []),
            dynamic_deps = shared + (["//lib/libc:c_shared", "//lib/libsys:sys_shared", "//lib/libelf:elf_shared"] if runtime else []),
            features = ["bsd_test_runtime_paths"] if runtime else [], linkopts = ["-pie", "-Wl,--gc-sections"],
            target_compatible_with = platform, visibility = ["//visibility:public"])
    bsd_component_sources(name = "source_inventory", groups = [":objects"], visibility = ["//visibility:public"])
    bsd_component_objects(name = "compiler_outputs", group = ":objects", pic = False, visibility = ["//visibility:public"])
    utility_installation(name = "install_manifest", program = name, manual = manual, package = "lldb", binary = ":" + name + "_installed")
    bsd_install_archive(name = "install_archive", manifests = [":install_manifest"],
        directories = {p: json.encode({"owner": "root", "group": "wheel", "mode": "0755", "tags": ["package=lldb", "dbg"]}) for p in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/bin"]},
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr", "//etc/mtree:BSD.include.dist": "/usr/include", "//etc/mtree:BSD.debug.dist": "/usr/lib"},
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"], visibility = ["//lib/clang:__pkg__"])
