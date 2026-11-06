# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":rpcsec_gss_shared",
        binary_name = name + "/librpcsec_gss.so.1", debug_name = name + "/librpcsec_gss.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/librpcsec_gss.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/librpcsec_gss.a", ["package=librpcsec_gss", "dev"], False),
        (":" + name + "_stripped", "/usr/lib/librpcsec_gss.so.1", ["package=librpcsec_gss"], False),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/librpcsec_gss.so.1.debug", ["package=librpcsec_gss", "dbg"], False),
    ]
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=librpcsec_gss-man"], "//conditions:default": ["package=librpcsec_gss-dev"]})
    for manual in ['rpcsec_gss.3', 'rpc_gss_seccreate.3', 'rpc_gss_set_defaults.3', 'rpc_gss_max_data_length.3', 'rpc_gss_get_error.3', 'rpc_gss_mech_to_oid.3', 'rpc_gss_oid_to_mech.3', 'rpc_gss_qop_to_num.3', 'rpc_gss_get_mechanisms.3', 'rpc_gss_get_mech_info.3', 'rpc_gss_get_versions.3', 'rpc_gss_is_installed.3', 'rpc_gss_set_svc_name.3', 'rpc_gss_getcred.3', 'rpc_gss_set_callback.3', 'rpc_gss_get_principal_name.3', 'rpc_gss_svc_max_data_length.3']:
        target = name + "_manual_" + manual
        bsd_compress(name = target, src = manual, output = name + "/" + manual + ".gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        files.append((":" + target, "/usr/share/man/man3/" + manual + ".gz", man_tags, True))
    entries = []
    for source, destination, tags, is_manual in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(manual = is_manual, name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/librpcsec_gss.so", target = "librpcsec_gss.so.1",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=librpcsec_gss", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
