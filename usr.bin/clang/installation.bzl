# SPDX-License-Identifier: BSD-2-Clause
"""Source-owned selection of the normal installed LLVM tool family."""
load("@bazel_skylib//lib:selects.bzl", "selects")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_manifest")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")

def _selected_targets(suffix):
    # The toolchain manifest closes manual hardlinks over ten utility owners,
    # including llvm-cov. Consume that closure once instead of repeating its
    # payloads in both leaf archives and the alias archive.
    return select({
        "//tools/build/bazel/config:clang_enabled": [
            "//usr.bin/clang/" + name + suffix
            for name in ["clang", "clang-scan-deps", "llvm-profdata"]
        ],
        "//conditions:default": [],
    }) + select({
        ":compiler_or_binutils": ["//usr.bin/clang/toolchain" + suffix],
        "//conditions:default": [],
    }) + select({
        "//tools/build/bazel/config:clang_format_or_extras_enabled": ["//usr.bin/clang/clang-format" + suffix],
        "//conditions:default": [],
    }) + select({
        "//tools/build/bazel/config:lld_enabled": ["//usr.bin/clang/lld" + suffix],
        "//conditions:default": [],
    }) + select({
        "//tools/build/bazel/config:lldb_enabled": [
            "//usr.bin/clang/lldb" + suffix,
            "//usr.bin/clang/lldb-server" + suffix,
        ],
        "//conditions:default": [],
    })

def llvm_family_installation():
    """Declare archives and a closed manifest from the same configured owners.

    This is the normal installed subtree, not the TOOLS_PREFIX bootstrap graph.
    CLANG_EXTRAS and compiler-disabled binutils-only installation remain explicit
    incompatibilities until their complete inventories and hardlinks are closed.
    """
    selects.config_setting_group(
        name = "compiler_or_binutils",
        match_any = ["//tools/build/bazel/config:clang_enabled", "//tools/build/bazel/config:llvm_binutils_enabled"],
    )
    native.config_setting(name = "compiler_disabled", flag_values = {"//tools/build/bazel/config:clang": "false"})
    selects.config_setting_group(
        name = "binutils_without_compiler",
        match_all = [":compiler_disabled", "//tools/build/bazel/config:llvm_binutils_enabled"],
    )
    compatibility = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"] + select({
        "//tools/build/bazel/config:clang_extras_enabled": ["@platforms//:incompatible"],
        ":binutils_without_compiler": ["@platforms//:incompatible"],
        "//conditions:default": [],
    })
    bsd_install_archive_set(
        name = "installation_archives",
        archives = _selected_targets(":install_archive"),
        target_compatible_with = compatibility,
        visibility = ["//visibility:public"],
    )
    # This is a typed installation contribution, not a package or a full world.
    # Strict manifest composition rejects duplicate destinations and bad links.
    bsd_install_manifest(
        name = "install_manifest",
        manifests = _selected_targets(":install_manifest"),
        target_compatible_with = compatibility,
        visibility = ["//visibility:public"],
    )
