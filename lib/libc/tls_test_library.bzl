# SPDX-License-Identifier: BSD-2-Clause
"""Original TLS test helper archives, DSOs and package-owned installation."""
load("@rules_cc//cc:defs.bzl", "cc_library", "cc_shared_library", "cc_import")
load("//tools/build/bazel:bsd_component_archive.bzl", "bsd_component_archive")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load(":test_policy.bzl", "libc_test_copts")

_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]

def tls_test_library(source, archive_name, soname, link_name = None):
    # Library regular objects are neither PIE nor PIC; shared objects use the
    # original small-PIC policy, with PIC defined only on that variant.
    cc_library(name = "objects", srcs = [source], deps = ["//contrib/atf:c_headers", "//lib/libc:shared_abi_interface"],
        copts = [flag for flag in libc_test_copts() if flag != "-fPIE"], features = ["bsd_small_pic"],
        linkstatic = True, target_compatible_with = _PLATFORM)
    bsd_component_archive(name = "static_archive", groups = [":objects"])
    # Unresolved callback/TLS symbols in the dlopen helper intentionally bind
    # to its original exporting main executable. Do not add framework libraries
    # just to hide that plugin ABI or change its original NEEDED contract.
    cc_shared_library(name = "shared", deps = [":objects"], shared_lib_name = soname,
        user_link_flags = ["-nodefaultlibs", "-Wl,-soname," + soname], target_compatible_with = _PLATFORM,
        visibility = ["//visibility:public"])
    cc_import(name = "link_interface", shared_library = ":shared", visibility = ["//visibility:public"])
    bsd_debug_split(name = "debug", src = ":shared", binary_name = "install/" + soname, debug_name = "install/" + soname + ".debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    native.filegroup(name = "symbols", srcs = [":debug"], output_group = "debug_files")
    directory = "/usr/tests/lib/libc/tls"
    entries = []
    for name, source_label, destination, tags in [
        ("archive", ":static_archive", directory + "/" + archive_name, ["package=tests"]),
        ("shared", ":debug", directory + "/" + soname, ["package=tests"]),
        ("symbols", ":symbols", "/usr/lib/debug" + directory + "/" + soname + ".debug", ["package=tests", "dbg"]),
    ]:
        target = "payload_" + name
        bsd_install_file(name = target, src = source_label, destination = destination, owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    if link_name:
        bsd_install_link(name = "install_alias", destination = directory + "/" + link_name, target = soname,
            kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=tests"])
        entries.append(":install_alias")
    bsd_install_manifest(name = "install_manifest", entries = entries, visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = directory, manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"], visibility = ["//visibility:public"], target_compatible_with = _PLATFORM)
