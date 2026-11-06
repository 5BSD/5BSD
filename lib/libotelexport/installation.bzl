# SPDX-License-Identifier: BSD-2-Clause
# What Make installs for the INTERNALLIB libotelexport: its two manuals with
# their MLINKS and the opentelemetry-proto licence (FILESGROUPS
# OTLP_LICENSES, package utilities).  No archive or header is installed.
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")

MANUALS = {
    "libotelexport": ['oe_profile', 'oe_signal_name', 'oe_otlp_config_signals', 'oe_text_new', 'oe_jsonl_new', 'oe_collapsed_new', 'oe_text_sink_new', 'oe_jsonl_sink_new', 'oe_jsonl_resource_new', 'oe_collapsed_sink_new', 'oe_otlp_new', 'oe_otlpjson_new', 'oe_sink_open', 'oe_sink_write', 'oe_sink_poll', 'oe_sink_flush', 'oe_sink_stream', 'oe_sink_path', 'oe_sink_close', 'oe_start', 'oe_event', 'oe_snapshot', 'oe_flush', 'oe_shutdown', 'oe_exporter_free', 'oe_traceparent_parse', 'oe_env_load', 'oe_env_free', 'oe_config_load', 'oe_resource_init', 'oe_otlp_config_env', 'oe_severity_text', 'oe_span', 'oe_host_detect', 'oe_host_arch_semconv', 'oe_resource_host', 'oe_id_random', 'oe_id_derive', 'oe_id_hex', 'oe_id_is_zero', 'oe_host_name', 'oe_host_arch', 'oe_os_version', 'oe_buf_init', 'oe_buf_free', 'oe_buf_append', 'oe_buf_appendstr', 'oe_buf_appendf', 'oe_buf_appendjson', 'oe_frame_format', 'oe_iso8601', 'oe_sink_reopen', 'oe_sink_reopen_request', 'oe_env_sink_open', 'oe_exporter_open'],
    "oe_sysconf": ['oe_sysconf_init', 'oe_sysconf_load', 'oe_sysconf_free', 'oe_headers_file_load', 'oe_attrs_free', 'oe_env_load_system', 'oe_service_open', 'oe_service_close', 'oe_service_flush', 'oe_drop_privileges'],
}

def library_installation(name):
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=utilities-man"], "//conditions:default": ["package=utilities-dev"]})
    entries = []
    for manual, aliases in MANUALS.items():
        bsd_compress(name = name + "_" + manual + "_compressed", src = manual + ".3", output = name + "/" + manual + ".3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        bsd_install_file(manual = True, name = name + "_" + manual + "_manual", src = ":" + name + "_" + manual + "_compressed", destination = "/usr/share/man/man3/" + manual + ".3.gz", owner = "root", group = "wheel", mode = "0444", install_tags = man_tags)
        entries.append(":" + name + "_" + manual + "_manual")
        for alias in aliases:
            target = name + "_" + alias
            bsd_install_link(manual = True, name = target, destination = "/usr/share/man/man3/" + alias + ".3.gz", target = "/usr/share/man/man3/" + manual + ".3.gz", kind = "hardlink", owner = "root", group = "wheel", mode = "0444", install_tags = man_tags)
            entries.append(":" + target)
    bsd_install_file(name = name + "_otlp_license", src = "//contrib/opentelemetry-proto:LICENSE", destination = "/usr/share/licenses/opentelemetry-proto/LICENSE", owner = "root", group = "wheel", mode = "0444", install_tags = ["package=utilities"])
    entries.append(":" + name + "_otlp_license")
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
