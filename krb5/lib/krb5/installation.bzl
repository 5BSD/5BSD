# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_pkgconfig.bzl", "bsd_header_pkgconfig")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")



def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":krb5_shared",
        binary_name = name + "/libkrb5.so.122", debug_name = name + "/libkrb5.so.122.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libkrb5.so.122",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libkrb5.a", ["package=kerberos", "dev"], False),
        (":" + name + "_stripped", "/usr/lib/libkrb5.so.122", ["package=kerberos", "lib"], False),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libkrb5.so.122.debug", ["package=kerberos", "dbg"], False),
    ]
    for pc in ["krb5", "mit-krb5"]:
        substitutions = {"prefix": "/usr", "exec_prefix": "${prefix}", "libdir": "/usr/lib", "includedir": "/usr/include",
            "DEFCCNAME": "FILE:/tmp/krb5cc_%{uid}", "DEFKTNAME": "FILE:/etc/krb5.keytab", "DEFCKTNAME": "FILE:/var/krb5/user/%{euid}/client.keytab"}
        if pc == "mit-krb5":
            substitutions["COM_ERR_LIB"] = "-lcom_err"
        bsd_header_pkgconfig(name = name + "_" + pc, template = "//crypto/krb5/src/build-tools:" + pc + ".pc.in",
            header = "//crypto/krb5/src:configure", version_patterns = ["^PACKAGE_VERSION='([^']+)'$"], version_field = "KRB5_VERSION",
            substitutions = substitutions, output = name + "/" + pc + ".pc",
            python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json", runtime = ["@bsd_sdk//toolchain:python_stdlib"])
        files.append((":" + name + "_" + pc, "/usr/libdata/pkgconfig/" + pc + ".pc", ["package=kerberos", "dev"], False))
    for manual in ['k5identity.5', 'k5login.5', 'krb5.conf.5', 'kerberos.7', 'kadm5.acl.5', 'kdc.conf.5']:
        package = "kerberos-kdc" if manual in ["kadm5.acl.5", "kdc.conf.5"] else "kerberos"
        bsd_compress(name = name + "_" + manual, src = "//crypto/krb5/src/man:" + manual[:-2] + ".man",
            output = name + "/" + manual + ".gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
            redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        files.append((":" + name + "_" + manual, "/usr/share/man/man" + manual[-1] + "/" + manual + ".gz",
            select({"//tools/build/bazel/config:split_manpages_enabled": ["package=" + package + "-man"], "//conditions:default": ["package=" + package]}), True))
    entries = []
    for source, destination, tags, is_manual in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(manual = is_manual, name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libkrb5.so", target = "libkrb5.so.122",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=kerberos", "dev"])
    for manual in ["k5identity.5", "k5login.5"]:
        target = name + "_alias_" + manual
        bsd_install_link(manual = True, name = target, destination = "/usr/share/man/man5/." + manual + ".gz", target = "/usr/share/man/man5/" + manual + ".gz",
            kind = "hardlink", owner = "root", group = "wheel", mode = "0444",
            install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=kerberos-man"], "//conditions:default": ["package=kerberos"]}))
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
