# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")



def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":radius_shared",
        binary_name = name + "/libradius.so.4", debug_name = name + "/libradius.so.4.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libradius.so.4",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        ("radlib_vs.h", "/usr/include/radlib_vs.h", ["package=utilities", "dev"]),
        ("radlib.h", "/usr/include/radlib.h", ["package=utilities", "dev"]),
        (":static_archive", "/usr/lib/libradius.a", ["package=utilities", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libradius.so.4", ["package=utilities"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libradius.so.4.debug", ["package=utilities", "dbg"]),
    ]
    bsd_compress(name = name + "_manual", src = "libradius.3",
        output = name + "/libradius.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
        redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/libradius.3.gz",
        select({"//tools/build/bazel/config:split_manpages_enabled": ["package=utilities-man"], "//conditions:default": ["package=utilities-dev"]})))
    bsd_compress(name = name + "_config_manual", src = "radius.conf.5",
        output = name + "/radius.conf.5.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
        redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_config_manual", "/usr/share/man/man5/radius.conf.5.gz",
        select({"//tools/build/bazel/config:split_manpages_enabled": ["package=utilities-man"], "//conditions:default": ["package=utilities"]})))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libradius.so", target = "libradius.so.4",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=utilities", "dev"])
    for alias in ['rad_acct_open', 'rad_add_server', 'rad_add_server_ex', 'rad_auth_open', 'rad_bind_to', 'rad_close', 'rad_config', 'rad_continue_send_request', 'rad_create_request', 'rad_create_response', 'rad_cvt_addr', 'rad_cvt_int', 'rad_cvt_string', 'rad_demangle', 'rad_demangle_mppe_key', 'rad_get_attr', 'rad_get_vendor_attr', 'rad_init_send_request', 'rad_put_addr', 'rad_put_attr', 'rad_put_int', 'rad_put_message_authentic', 'rad_put_string', 'rad_put_vendor_addr', 'rad_put_vendor_attr', 'rad_put_vendor_int', 'rad_put_vendor_string', 'rad_receive_request', 'rad_request_authenticator', 'rad_send_request', 'rad_send_response', 'rad_server_open', 'rad_server_secret', 'rad_strerror']:
        target = name + "_manual_" + alias
        bsd_install_link(name = target, destination = "/usr/share/man/man3/" + alias + ".3.gz",
            target = "/usr/share/man/man3/libradius.3.gz", kind = "hardlink", owner = "root", group = "wheel",
            mode = "0444", install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=utilities-man"], "//conditions:default": ["package=utilities-dev"]}))
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
