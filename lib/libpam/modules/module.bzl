# SPDX-License-Identifier: BSD-2-Clause
load("@rules_cc//cc:defs.bzl", "cc_library", "cc_import", "cc_shared_library")
load("//tools/build/bazel:bsd_dtrace.bzl", "bsd_dtrace_header", "bsd_dtrace_cc_objects")
load("//tools/build/bazel:bsd_component_archive.bzl", "bsd_component_archive")
load(":installation.bzl", "module_installation")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_TRACE = "//tools/build/bazel/config:dtrace_enabled"

def pam_module(name, srcs, provider = None, deps = [], dynamic_deps = [], manuals = None, local_defines = [], copts = [], package = "pam", manual_sources = {}):
    """One PAM module per package, with separate static registration objects."""
    if provider:
        bsd_dtrace_header(
            name = "provider", source = provider, output = name + "_provider.h",
            flags = ["-C", "-x", "nolibs"], object_path_mode = "relative",
            dtrace = "//cddl/usr.sbin/dtrace:dtrace", cpp = "@bsd_sdk//toolchain:bin/cpp",
            linker = "@bsd_sdk//toolchain:bin/ld.lld", objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy",
            drti = "//cddl/lib/drti:drti",
            runtime_libraries = ['//cddl/lib/libdtrace:dtrace_shared', '//cddl/lib/libctf:ctf_shared', '//lib/libelf:elf_shared', '//lib/libproc:proc_shared', '//cddl/lib/libspl:spl_shared', '//lib/libxo/libxo:xo_shared', '//lib/libutil:util_shared', '//lib/libprocstat:procstat_shared', '//lib/librtld_db:rtld_db_shared', '//lib/libcxxrt:cxxrt_shared', '//lib/libz:z_shared', '//lib/libkvm:kvm_shared'],
            tool_inputs = [ "@bsd_sdk//toolchain:compile_inputs",
                "@bsd_sdk//toolchain:link_inputs", "@bsd_sdk//toolchain:objcopy_inputs"], static_anchor = False,
        )
        cc_library(name = "provider_headers", hdrs = [":provider"], strip_include_prefix = ".")
    for variant in ["shared", "static"]:
        cc_library(name = variant + "_objects", srcs = srcs,
            deps = ["//contrib/openpam:headers"] + deps + (select({_TRACE: [":provider_headers"], "//conditions:default": []}) if provider else []),
            local_defines = ["OPENPAM_DEBUG"] + local_defines + (["OPENPAM_STATIC_MODULES"] if variant == "static" else []) + (select({_TRACE: ["WITH_DTRACE"], "//conditions:default": []}) if provider else []),
            copts = copts, linkstatic = True, target_compatible_with = _PLATFORM)
        if provider:
            bsd_dtrace_cc_objects(name = variant + "_traced", library = ":" + variant + "_objects", provider = ":provider",
                provider_object = name + "_provider", copy_runner = "//tools/build/bazel:dtrace_copy_runner")
            for group in ["regular_objects", "pic_objects", "regular_provider", "pic_provider"]:
                native.filegroup(name = variant + "_" + group, srcs = [":" + variant + "_traced"], output_group = group)
            cc_import(name = variant + "_provider", objects = [":" + variant + "_regular_provider"], pic_objects = [":" + variant + "_pic_provider"], alwayslink = True)
            cc_import(name = variant + "_rewritten", objects = [":" + variant + "_regular_objects"], pic_objects = [":" + variant + "_pic_objects"], deps = [":" + variant + "_provider"])
    cc_library(name = "module", deps = ["//lib/libpam/libpam:pam"] + deps + (select({_TRACE: [":shared_rewritten"], "//conditions:default": [":shared_objects"]}) if provider else [":shared_objects"]))
    cc_shared_library(name = name, deps = [":module"], dynamic_deps = ["//lib/libpam/libpam:pam_shared"] + dynamic_deps,
        shared_lib_name = name + ".so.6", user_link_flags = ["-Wl,-soname," + name + ".so.6", "-Wl,--fatal-warnings,--warn-shared-textrel"],
        target_compatible_with = _PLATFORM, visibility = ["//visibility:public"])
    bsd_component_archive(name = "static_archive", groups = select({_TRACE: [":static_rewritten", ":static_provider"], "//conditions:default": [":static_objects"]}) if provider else [":static_objects"], visibility = ["//visibility:public"])
    module_installation(name = "install_manifest", module = name, manuals = manuals, package = package, manual_sources = manual_sources)
    bsd_install_archive(
        name = "install_archive",
        manifests = [":install_manifest"],
        directories = {d: json.encode({"owner": "root", "group": "wheel", "mode": "0755", "tags": ["package=" + package, "dbg"]}) for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/lib"]},
        mtree_specs = {
            "//etc/mtree:BSD.root.dist": "/",
            "//etc/mtree:BSD.usr.dist": "/usr",
            "//etc/mtree:BSD.include.dist": "/usr/include",
            "//etc/mtree:BSD.debug.dist": "/usr/lib",
        },
        passwd = "//etc:master.passwd",
        group = "//etc:group",
        mtree = "@bsd_sdk//toolchain:extra_mtree",
        epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python",
        python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"],
    )
