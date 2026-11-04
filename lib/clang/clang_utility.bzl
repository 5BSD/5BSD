# SPDX-License-Identifier: BSD-2-Clause
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")
load("//tools/build/bazel:bsd_llvm_targets.bzl", "bsd_llvm_targets")
load("//tools/build/bazel:bsd_clang_defaults.bzl", "bsd_clang_defaults")
load("//tools/build/bazel:bsd_component_archive.bzl", "bsd_component_sources")
load("//tools/build/bazel:bsd_tablegen.bzl", "bsd_tablegen")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")

def clang_utility(name, srcs, options = None, deps = [], compatible_with = []):
    """Default shared Clang utility with declared inputs and installation."""
    if options:
        bsd_tablegen(name = "options", src = options,
            includes = ["//contrib/llvm-project/llvm/include:llvm/Option/OptParser.td"],
            include_dirs = ["contrib/llvm-project/llvm/include"], flags = ["-gen-opt-parser-defs"],
            output = "Opts.inc", tool = "//usr.bin/clang/llvm-tblgen:bootstrap")
        cc_library(name = "option_headers", hdrs = [":options"], strip_include_prefix = ".")
    bsd_llvm_targets(name = "registered_targets")
    bsd_clang_defaults(name = "compiler_defaults")
    platform = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"] + compatible_with
    cc_library(name = "objects", srcs = srcs,
        deps = deps + ([":option_headers"] if options else []) + ["//contrib/llvm-project/clang/include:headers", "//lib/clang/libllvm:directive_headers", "//lib/clang/libllvm:target_definition_headers", ":registered_targets", ":compiler_defaults", "//contrib/llvm-project/llvm/include:headers", "//contrib/llvm-project/libcxx/include:headers", "//lib/clang/libllvm:intrinsic_headers", "//lib/clang/libllvm:ir_generated_headers", "//usr.bin/clang/llvm-min-tblgen:value_type_headers"],
        copts = ["-fPIE", "-std=c++17", "-nostdinc++", "-fno-exceptions", "-fno-rtti", "-fvisibility-inlines-hidden", "-ffunction-sections", "-fdata-sections"] + select({"//tools/build/bazel/config:llvm_full_debuginfo_enabled": ["-g"], "//conditions:default": ["-gline-tables-only"]}),
        local_defines = select({"//tools/build/bazel/config:clang_full_enabled": ["CLANG_ENABLE_STATIC_ANALYZER"], "//conditions:default": []}) + ["__STDC_CONSTANT_MACROS", "__STDC_FORMAT_MACROS", "__STDC_LIMIT_MACROS", "HAVE_VCS_VERSION_INC"] + select({"//tools/build/bazel/config:llvm_assertions_enabled": [], "//conditions:default": ["NDEBUG"]}),
        target_compatible_with = platform)
    [cc_binary(name = variant, deps = [":objects", "//lib/clang/libclang:clang", "//lib/clang/libllvm:llvm", "//lib/libz:z", "//lib/libzstd:zstd", "//lib/libc++:cxx", "//lib/libexecinfo:execinfo", "//lib/ncurses/ncurses:ncurses", "//lib/libthr:thr"] + (["//lib/libc:shared_link_interface"] if runtime else []),
        dynamic_deps = ["//lib/clang/libclang:clang_shared","//lib/clang/libllvm:llvm_shared", "//lib/libz:z_shared", "//lib/libzstd:zstd_shared", "//lib/libc++:cxx_shared", "//lib/libcxxrt:cxxrt_shared", "//lib/msun:m_shared", "//lib/libexecinfo:execinfo_shared", "//lib/ncurses/ncurses:ncurses_shared", "//lib/libthr:thr_shared"] + (["//lib/libc:c_shared", "//lib/libsys:sys_shared", "//lib/libelf:elf_shared"] if runtime else []),
        features = ["bsd_test_runtime_paths"] if runtime else [], linkopts = ["-pie", "-Wl,--gc-sections"],
        target_compatible_with = platform, visibility = ["//visibility:public"],
    ) for variant, runtime in [(name, True), (name + "_installed", False)]]
    bsd_component_sources(name = "source_inventory", groups = [":objects"], visibility = ["//visibility:public"])

    utility_installation(name = "install_manifest", program = name, binary = ":" + name + "_installed", manual = None, package = "clang")
    bsd_install_archive(name = "install_archive", visibility = ["//usr.bin/clang:__pkg__"], manifests = [":install_manifest"],
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr", "//etc/mtree:BSD.include.dist": "/usr/include", "//etc/mtree:BSD.debug.dist": "/usr/lib"},
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"])
