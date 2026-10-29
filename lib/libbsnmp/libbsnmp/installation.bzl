# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")



def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":bsnmp_shared",
        binary_name = name + "/libbsnmp.so.7", debug_name = name + "/libbsnmp.so.7.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libbsnmp.so.7",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libbsnmp.a", ["package=bsnmp", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libbsnmp.so.7", ["package=bsnmp"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libbsnmp.so.7.debug", ["package=bsnmp", "dbg"]),
    ]
    files += [("//contrib/bsnmp/lib:" + header, "/usr/include/bsnmp/" + header, ["package=bsnmp", "dev"])
              for header in ["asn1.h", "snmp.h", "snmpagent.h", "snmpclient.h"]]
    files.append(("//contrib/bsnmp/lib:tc.def", "/usr/share/snmp/defs/tc.def", ["package=bsnmp"]))
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=bsnmp-man"], "//conditions:default": ["package=bsnmp-dev"]})
    for manual in ["asn1.3", "bsnmpagent.3", "bsnmpclient.3", "bsnmplib.3"]:
        target = name + "_manual_" + manual
        bsd_compress(name = target, src = "//contrib/bsnmp/lib:" + manual, output = name + "/" + manual + ".gz",
            arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
            redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        files.append((":" + target, "/usr/share/man/man3/" + manual + ".gz", man_tags))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libbsnmp.so", target = "libbsnmp.so.7",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=bsnmp", "dev"])
    aliases = {
            "asn1.3": [
                    "asn_append_oid",
                    "asn_commit_header",
                    "asn_compare_oid",
                    "asn_get_counter64_raw",
                    "asn_get_header",
                    "asn_get_integer",
                    "asn_get_integer_raw",
                    "asn_get_ipaddress",
                    "asn_get_ipaddress_raw",
                    "asn_get_null",
                    "asn_get_null_raw",
                    "asn_get_objid",
                    "asn_get_objid_raw",
                    "asn_get_octetstring",
                    "asn_get_octetstring_raw",
                    "asn_get_sequence",
                    "asn_get_timeticks",
                    "asn_get_uint32_raw",
                    "asn_is_suboid",
                    "asn_oid2str",
                    "asn_oid2str_r",
                    "asn_put_counter64",
                    "asn_put_exception",
                    "asn_put_header",
                    "asn_put_integer",
                    "asn_put_ipaddress",
                    "asn_put_null",
                    "asn_put_objid",
                    "asn_put_octetstring",
                    "asn_put_temp_header",
                    "asn_put_timeticks",
                    "asn_put_uint32",
                    "asn_skip",
                    "asn_slice_oid"
            ],
            "bsnmpagent.3": [
                    "snmp_debug",
                    "snmp_dep_commit",
                    "snmp_dep_finish",
                    "snmp_dep_lookup",
                    "snmp_dep_rollback",
                    "snmp_depop_t",
                    "snmp_get",
                    "snmp_getbulk",
                    "snmp_getnext",
                    "snmp_init_context",
                    "snmp_make_errresp",
                    "snmp_op_t",
                    "snmp_set",
                    "snmp_trace",
                    "tree_size"
            ],
            "bsnmpclient.3": [
                    "snmp_add_binding",
                    "snmp_client",
                    "snmp_client_init",
                    "snmp_client_set_host",
                    "snmp_client_set_port",
                    "snmp_close",
                    "snmp_dialog",
                    "snmp_discover_engine",
                    "snmp_oid_append",
                    "snmp_open",
                    "snmp_parse_server",
                    "snmp_pdu_check",
                    "snmp_pdu_create",
                    "snmp_pdu_send",
                    "snmp_receive",
                    "snmp_send_cb_f",
                    "snmp_table_cb_f",
                    "snmp_table_fetch",
                    "snmp_table_fetch_async",
                    "snmp_timeout_cb_f",
                    "snmp_timeout_start_f",
                    "snmp_timeout_stop_f"
            ],
            "bsnmplib.3": [
                    "TRUTH_GET",
                    "TRUTH_MK",
                    "TRUTH_OK",
                    "snmp_calc_keychange",
                    "snmp_get_local_keys",
                    "snmp_passwd_to_keys",
                    "snmp_pdu_decode",
                    "snmp_pdu_decode_header",
                    "snmp_pdu_decode_scoped",
                    "snmp_pdu_decode_secmode",
                    "snmp_pdu_dump",
                    "snmp_pdu_encode",
                    "snmp_pdu_free",
                    "snmp_pdu_init_secparams",
                    "snmp_value_copy",
                    "snmp_value_free",
                    "snmp_value_parse"
            ]
    }
    for original, names in aliases.items():
        for alias in names:
            target = name + "_alias_" + alias
            bsd_install_link(name = target, destination = "/usr/share/man/man3/" + alias + ".3.gz",
                target = "/usr/share/man/man3/" + original + ".gz", kind = "hardlink", owner = "root", group = "wheel", mode = "0444", install_tags = man_tags)
            entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
