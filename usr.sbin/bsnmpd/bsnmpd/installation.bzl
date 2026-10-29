# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_template.bzl", "bsd_template")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")

def daemon_installation():
    for manual in ["bsnmpd.1", "snmpmod.3"]:
        bsd_template(name = "filtered_" + manual, template = "//contrib/bsnmp/snmpd:" + manual,
            output = "manuals/" + manual, substitutions = {"@MODPATH@": "/usr/lib/", "@DEFPATH@": "/usr/share/snmp/defs/", "@MIBSPATH@": "/usr/share/snmp/mibs/"})
    utility_installation(name = "install_program", program = "bsnmpd", manual = ":filtered_bsnmpd.1", package = "bsnmp", bindir = "/usr/sbin")
    bsd_compress(name = "module_manual", src = ":filtered_snmpmod.3", output = "snmpmod.3.gz",
        arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=bsnmp-man"], "//conditions:default": ["package=bsnmp-dev"]})
    files = [
        ("snmpd.config", "/etc/snmpd.config", "0600", ["package=bsnmp", "config"]),
        (":module_manual", "/usr/share/man/man3/snmpmod.3.gz", "0444", man_tags),
        ("//contrib/bsnmp/snmpd:tree.def", "/usr/share/snmp/defs/tree.def", "0444", ["package=bsnmp"]),
    ] + [("//contrib/bsnmp/snmpd:" + name, "/usr/share/snmp/mibs/" + name, "0444", ["package=bsnmp"]) for name in ["FOKUS-MIB.txt", "BEGEMOT-MIB.txt", "BEGEMOT-SNMPD.txt"]]
    entries = []
    for source, destination, mode, tags in files:
        name = "file_" + destination.replace("/", "_")
        bsd_install_file(name = name, src = source, destination = destination, mode = mode, owner = "root", group = "wheel", install_tags = tags)
        entries.append(":" + name)
    for alias in ALIASES:
        name = "alias_" + alias
        bsd_install_link(name = name, destination = "/usr/share/man/man3/" + alias + ".3.gz", target = "/usr/share/man/man3/snmpmod.3.gz", kind = "hardlink", owner = "root", group = "wheel", mode = "0444", install_tags = man_tags)
        entries.append(":" + name)
    bsd_install_manifest(name = "install_data", entries = entries)
    bsd_install_archive(name = "install_archive", manifests = [":install_program", ":install_data"],
        directories = {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsnmp","dbg"]}' for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/sbin"]} | {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsnmp"]}' for d in ["/usr/share/snmp/defs", "/usr/share/snmp/mibs"]} | {"/etc": '{"owner":"root","group":"wheel","mode":"0755","tags":["package=utilities"]}'},
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr", "//etc/mtree:BSD.debug.dist": "/usr/lib"},
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"], visibility = ["//visibility:public"])

ALIASES = [
    "FIND_OBJECT_INT",
    "FIND_OBJECT_INT_LINK",
    "FIND_OBJECT_INT_LINK_INDEX",
    "FIND_OBJECT_OID",
    "FIND_OBJECT_OID_LINK",
    "FIND_OBJECT_OID_LINK_INDEX",
    "INSERT_OBJECT_INT",
    "INSERT_OBJECT_INT_LINK",
    "INSERT_OBJECT_INT_LINK_INDEX",
    "INSERT_OBJECT_OID",
    "INSERT_OBJECT_OID_LINK",
    "INSERT_OBJECT_OID_LINK_INDEX",
    "NEXT_OBJECT_INT",
    "NEXT_OBJECT_INT_LINK",
    "NEXT_OBJECT_INT_LINK_INDEX",
    "NEXT_OBJECT_OID",
    "NEXT_OBJECT_OID_LINK",
    "NEXT_OBJECT_OID_LINK_INDEX",
    "bsnmpd_get_target_stats",
    "bsnmpd_get_usm_stats",
    "bsnmpd_reset_usm_stats",
    "buf_alloc",
    "buf_size",
    "comm_define",
    "community",
    "fd_deselect",
    "fd_resume",
    "fd_select",
    "fd_suspend",
    "get_ticks",
    "index_append",
    "index_append_off",
    "index_compare",
    "index_compare_off",
    "index_decode",
    "ip_commit",
    "ip_get",
    "ip_rollback",
    "ip_save",
    "or_register",
    "or_unregister",
    "oid_commit",
    "oid_get",
    "oid_rollback",
    "oid_save",
    "oid_usmNotInTimeWindows",
    "oid_usmUnknownEngineIDs",
    "oid_zeroDotZero",
    "reqid_allocate",
    "reqid_base",
    "reqid_istype",
    "reqid_next",
    "reqid_type",
    "snmp_input_finish",
    "snmp_input_start",
    "snmp_output",
    "snmp_pdu_auth_access",
    "snmp_send_port",
    "snmp_send_trap",
    "snmpd_target_stat",
    "snmpd_usmstats",
    "start_tick",
    "string_commit",
    "string_free",
    "string_get",
    "string_get_max",
    "string_rollback",
    "string_save",
    "systemg",
    "this_tick",
    "timer_start",
    "timer_start_repeat",
    "timer_stop",
    "target_activate_address",
    "target_address",
    "target_delete_address",
    "target_delete_notify",
    "target_delete_param",
    "target_first_address",
    "target_first_notify",
    "target_first_param",
    "target_flush_all",
    "target_next_address",
    "target_next_notify",
    "target_next_param",
    "target_new_address",
    "target_new_notify",
    "target_new_param",
    "target_notify",
    "target_param",
    "usm_delete_user",
    "usm_find_user",
    "usm_first_user",
    "usm_flush_users",
    "usm_next_user",
    "usm_new_user",
    "usm_user"
]
