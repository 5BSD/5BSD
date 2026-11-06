# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")



def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":gssapi_shared",
        binary_name = name + "/libgssapi.so.10", debug_name = name + "/libgssapi.so.10.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libgssapi.so.10",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libgssapi.a", ["package=runtime", "dev"], False),
        (":" + name + "_stripped", "/usr/lib/libgssapi.so.10", ["package=runtime"], False),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libgssapi.so.10.debug", ["package=runtime", "dbg"], False),
    ]
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=runtime-man"], "//conditions:default": ["package=runtime-dev"]})
    for manual in ['gssapi.3', 'gss_accept_sec_context.3', 'gss_acquire_cred.3', 'gss_add_cred.3', 'gss_add_oid_set_member.3', 'gss_canonicalize_name.3', 'gss_compare_name.3', 'gss_context_time.3', 'gss_create_empty_oid_set.3', 'gss_delete_sec_context.3', 'gss_display_name.3', 'gss_display_status.3', 'gss_duplicate_name.3', 'gss_export_name.3', 'gss_export_sec_context.3', 'gss_get_mic.3', 'gss_import_name.3', 'gss_import_sec_context.3', 'gss_indicate_mechs.3', 'gss_init_sec_context.3', 'gss_inquire_context.3', 'gss_inquire_cred.3', 'gss_inquire_cred_by_mech.3', 'gss_inquire_mechs_for_name.3', 'gss_inquire_names_for_mech.3', 'gss_process_context_token.3', 'gss_release_buffer.3', 'gss_release_cred.3', 'gss_release_name.3', 'gss_release_oid_set.3', 'gss_test_oid_set_member.3', 'gss_unwrap.3', 'gss_verify_mic.3', 'gss_wrap.3', 'gss_wrap_size_limit.3', 'mech.5']:
        target = name + "_compressed_" + manual
        bsd_compress(name = target, src = manual, output = name + "/" + manual + ".gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        files.append((":" + target, "/usr/share/man/man" + manual[-1] + "/" + manual + ".gz", man_tags, True))
    entries = []
    for source, destination, tags, is_manual in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(manual = is_manual, name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libgssapi.so", target = "libgssapi.so.10",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=runtime", "dev"])
    for original, alias in [('gss_get_mic.3', 'gss_sign.3'), ('gss_unwrap.3', 'gss_unseal.3'), ('gss_verify_mic.3', 'gss_verify.3'), ('gss_wrap.3', 'gss_seal.3'), ('mech.5', 'qop.5')]:
        target = name + "_alias_" + alias
        bsd_install_link(manual = True, name = target, destination = "/usr/share/man/man" + alias[-1] + "/" + alias + ".gz", target = "/usr/share/man/man" + original[-1] + "/" + original + ".gz", kind = "hardlink", owner = "root", group = "wheel", mode = "0444", install_tags = man_tags)
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
