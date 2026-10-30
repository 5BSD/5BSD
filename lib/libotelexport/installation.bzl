# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
def library_installation(name):
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=utilities-man"], "//conditions:default": ["package=utilities-dev"]})
    bsd_compress(name = name + "_compressed", src = "libotelexport.3", output = name + "/libotelexport.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    bsd_install_file(name = name + "_manual", src = ":" + name + "_compressed", destination = "/usr/share/man/man3/libotelexport.3.gz", owner = "root", group = "wheel", mode = "0444", install_tags = man_tags)
    entries = [":" + name + "_manual"]
    for manual in ['oe_text_new', 'oe_jsonl_new', 'oe_collapsed_new', 'oe_otlp_new', 'oe_start', 'oe_event', 'oe_snapshot', 'oe_flush', 'oe_shutdown', 'oe_exporter_free', 'oe_report_drops', 'oe_env_load', 'oe_env_free', 'oe_host_name', 'oe_host_arch', 'oe_os_version', 'oe_buf_init', 'oe_buf_free', 'oe_buf_append', 'oe_buf_appendstr', 'oe_buf_appendf', 'oe_buf_appendjson', 'oe_frame_format', 'oe_iso8601']:
        alias = name + "_" + manual
        bsd_install_link(name = alias, destination = "/usr/share/man/man3/" + manual + ".3.gz", target = "/usr/share/man/man3/libotelexport.3.gz", kind = "hardlink", owner = "root", group = "wheel", mode = "0444", install_tags = man_tags)
        entries.append(":" + alias)
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
