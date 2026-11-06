# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")
load(":installation_data.bzl", "PAM_HEADERS", "PAM_MANUALS")
def pam_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":pam_shared", binary_name = name + "/libpam.so.6", debug_name = name + "/libpam.so.6.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libpam.so.6",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":" + name + "_stripped", "/usr/lib/libpam.so.6", ["package=pam", "lib"], False),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libpam.so.6.debug", ["package=pam", "dbg"], False),
        ("security/pam_mod_misc.h", "/usr/include/security/pam_mod_misc.h", ["package=pam", "dev"], False),
    ]
    for header in PAM_HEADERS:
        files.append(("//contrib/openpam:include/" + header, "/usr/include/" + header, ["package=pam", "dev"], False))
    for manual in PAM_MANUALS + ["pam.conf.5"]:
        target = name + "_manual_" + manual
        bsd_compress(name = target, src = "//contrib/openpam:doc/man/" + manual, output = name + "/" + manual + ".gz",
            arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=pam-man"], "//conditions:default": ["package=pam"] if manual == "pam.conf.5" else ["package=pam-dev"]})
        files.append((":" + target, "/usr/share/man/man" + manual.split(".")[-1] + "/" + manual + ".gz", tags, True))
    entries = []
    for source, destination, tags, is_manual in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(manual = is_manual, name = target, src = source, destination = destination, owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libpam.so", target = "libpam.so.6", kind = "symlink",
        owner = "root", group = "wheel", mode = "0755", install_tags = ["package=pam", "dev"])
    bsd_install_link(manual = True, name = name + "_manual_alias", destination = "/usr/share/man/man5/pam.d.5.gz", target = "/usr/share/man/man5/pam.conf.5.gz", kind = "hardlink",
        owner = "root", group = "wheel", mode = "0444", install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=pam-man"], "//conditions:default": ["package=pam"]}))
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link", ":" + name + "_manual_alias"], visibility = ["//visibility:public"])
