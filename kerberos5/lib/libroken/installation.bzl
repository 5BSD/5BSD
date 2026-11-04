# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

# Original public include inventory; roken.h is generated for the platform.
_HEADERS = ["roken-common.h", "base64.h", "getarg.h", "hex.h", "parse_bytes.h", "parse_time.h", "parse_units.h", "resolve.h", "rtbl.h", "xdbm.h"]

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":roken_shared",
        binary_name = name + "/libroken.so.11", debug_name = name + "/libroken.so.11.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libroken.so.11",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libroken.a", ["package=kerberos", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libroken.so.11", ["package=kerberos", "lib"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libroken.so.11.debug", ["package=kerberos", "dbg"]),
        ("//kerberos5/tools/make-roken:roken_header", "/usr/include/roken.h", ["package=kerberos", "dev"]),
    ] + [("//crypto/heimdal/lib/roken:" + header, "/usr/include/" + header, ["package=kerberos", "dev"]) for header in _HEADERS]
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libroken.so", target = "libroken.so.11",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=kerberos", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
