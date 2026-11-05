# SPDX-License-Identifier: BSD-2-Clause
"""Native production image and original capability-bundle installation."""
load("@rules_cc//cc:defs.bzl", "cc_binary")
load("//tools/build/bazel:bsd_capimage.bzl", "bsd_capimage_policy")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_directory", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")

_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_BUNDLE = "/Capabilities/System/SwitchBoardControl.cap"
_UNIT = _BUNDLE + "/Units/switchboardctl.unit"
_LIBS = ["//lib/libcapbundle:capbundle", "//lib/libcapsulert:capsulert", "//lib/libservice:service", "//lib/libucl:ucl", "//lib/libelf:elf", "//lib/libmd:md_link"]
_SHARED = ["//lib/libcapbundle:capbundle_shared", "//lib/libcapsulert:capsulert_shared", "//lib/libservice:service_shared", "//lib/libucl:ucl_shared", "//lib/libelf:elf_shared", "//lib/libmd:md_shared"]
# The original default WARNS vector; policy/PIE inputs are declared separately.
_WARNINGS = [
    "-Wall", "-Wno-format-y2k", "-W", "-Wno-unused-parameter",
    "-Wstrict-prototypes", "-Wmissing-prototypes", "-Wpointer-arith", "-Wreturn-type",
    "-Wcast-qual", "-Wwrite-strings", "-Wswitch", "-Wshadow", "-Wunused-parameter",
    "-Wcast-align", "-Wchar-subscripts", "-Wnested-externs", "-Wold-style-definition",
    "-Wno-pointer-sign", "-Wdate-time", "-Wmissing-variable-declarations", "-Wthread-safety",
    "-Wno-empty-body", "-Wno-string-plus-int", "-Wno-unused-const-variable",
    "-Wno-error=unused-but-set-parameter", "-Wno-error=cast-function-type-mismatch",
]

def switchboardctl_production():
    # Raw policy embedding is not a signature or verified-boot claim.
    bsd_capimage_policy(name = "policy_assembly", src = "capbundle/Unit.ucl")
    cc_binary(
        name = "switchboardctl",
        srcs = ["switchboardctl.c", "deps.c", "install.c", "personal.c", "verify.c", "graph.c", "switchboardctl.h", ":policy_assembly"],
        deps = _LIBS + ["//lib/libcapbundle:internal_headers"],
        dynamic_deps = _SHARED,
        copts = ["-std=gnu17", "-fPIE", "-DPIC", "-pipe", "-fno-common",
                 "-Wno-format-zero-length", "-Wsystem-headers", "-Qunused-arguments"] +
            select({"//tools/build/bazel/config:werror_enabled": ["-Werror"], "//conditions:default": []}) + _WARNINGS,
        linkopts = ["-pie", "-Wl,-z,now", "-Wl,-z,relro"],
        target_compatible_with = _PLATFORM,
        visibility = ["//visibility:public"],
    )
    native.filegroup(name = "source_objects", srcs = [":switchboardctl"], output_group = "compilation_outputs", visibility = ["//visibility:public"])
    utility_installation(name = "program_install", program = "switchboardctl", manual = "switchboardctl.8",
        package = "switchboardctl", bindir = _UNIT + "/bin", man_section = "8", keep_sections = [".5bsd.policy"])
    entries = []
    for name, source, destination in [
        ("bundle", "capbundle/Bundle.ucl", _BUNDLE + "/Bundle.ucl"),
        ("policy", "capbundle/Unit.ucl", _UNIT + "/Unit.ucl"),
    ]:
        bsd_install_file(name = name + "_install", src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = ["package=switchboardctl"])
        entries.append(":" + name + "_install")
    bsd_install_link(name = "command_alias", destination = "/usr/sbin/switchboardctl",
        target = "../.." + _UNIT + "/bin/switchboardctl", kind = "symlink",
        owner = "root", group = "wheel", mode = "0755", install_tags = ["package=switchboardctl"])
    entries.append(":command_alias")
    for index, directory in enumerate([_BUNDLE, _BUNDLE + "/Units", _UNIT, _UNIT + "/bin"]):
        name = "bundle_directory_" + str(index)
        bsd_install_directory(name = name, destination = directory,
            owner = "root", group = "wheel", mode = "0755", install_tags = ["package=switchboardctl"])
        entries.append(":" + name)
    for index, directory in enumerate(["/Capabilities", "/Capabilities/System", _BUNDLE, _BUNDLE + "/Units", _UNIT, _UNIT + "/bin"]):
        name = "debug_directory_" + str(index)
        bsd_install_directory(name = name, destination = "/usr/lib/debug" + directory,
            owner = "root", group = "wheel", mode = "0755", install_tags = ["package=switchboardctl", "dbg"])
        entries.append(":" + name)
    bsd_install_manifest(name = "install_manifest", manifests = [":program_install"], entries = entries, visibility = ["//visibility:public"])
    for name, full in [("production_install_archive", False), ("install_archive", True)]:
        bsd_install_archive(name = name, manifests = [":install_manifest"],
            target_compatible_with = _PLATFORM + (select({"//tools/build/bazel/config:tests_enabled": ["@platforms//:incompatible"], "//conditions:default": []}) if full else []),
            mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr", "//etc/mtree:BSD.debug.dist": "/usr/lib"},
            passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
            python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
            runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"], visibility = ["//visibility:public"])
