# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_pkgconfig.bzl", "bsd_header_pkgconfig")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")



def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":kdb5_shared",
        binary_name = name + "/libkdb5.so.122", debug_name = name + "/libkdb5.so.122.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libkdb5.so.122",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libkdb5.a", ["package=kerberos", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libkdb5.so.122", ["package=kerberos", "lib"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libkdb5.so.122.debug", ["package=kerberos", "dbg"]),
    ]
    bsd_header_pkgconfig(name = name + "_pc", template = "//crypto/krb5/src/build-tools:kdb.pc.in",
        header = "//crypto/krb5/src:configure", version_patterns = ["^PACKAGE_VERSION='([^']+)'$"], version_field = "KRB5_VERSION",
        substitutions = {"prefix": "/usr", "exec_prefix": "${prefix}", "libdir": "/usr/lib", "includedir": "/usr/include", "KDB5_DB_LIB": ""},
        output = name + "/kdb.pc", python = "@bsd_sdk//toolchain:extra_python",
        python_home = "@bsd_sdk//toolchain:python-home/runtime.json", runtime = ["@bsd_sdk//toolchain:python_stdlib"])
    files.append((":" + name + "_pc", "/usr/libdata/pkgconfig/kdb.pc", ["package=kerberos", "dev"]))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libkdb5.so", target = "libkdb5.so.122",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=kerberos", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
