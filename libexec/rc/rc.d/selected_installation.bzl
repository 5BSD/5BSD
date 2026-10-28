# SPDX-License-Identifier: BSD-2-Clause
"""Service groups controlled by the existing shared native build settings."""
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest")
_GROUPS = {
    "audit": ("audit", ["auditd", "auditdistd"]),
    "jail": ("jail", ["jail"]),
    "pf": ("pf", ["pf", "pflog", "pfsync", "ftp-proxy", "tftpproxy"]),
    "nis": ("yp", ["ypbind", "ypldap", "yppasswdd", "ypserv", "ypset", "ypupdated", "ypxfrd", "nisdomain"]),
    "ns_caching": ("rc", ["nscd"]),
    "kerberos_support": ("gssd", ["gssd"]),
}

def selected_installation(name):
    entries = []
    for setting, (package, services) in _GROUPS.items():
        group_entries = []
        for service in services:
            target = name + "_" + service
            bsd_install_file(name = target, src = service, destination = "/etc/rc.d/" + service,
                owner = "root", group = "wheel", mode = "0555", install_tags = ["package=" + package, "config"])
            group_entries.append(":" + target)
        entries = entries + select({"//tools/build/bazel/config:" + setting + "_enabled": group_entries, "//conditions:default": []})
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
