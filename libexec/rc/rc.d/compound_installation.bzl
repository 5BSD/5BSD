# SPDX-License-Identifier: BSD-2-Clause
"""Architecture and compound-option rc.d selections."""
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest")
def compound_installation(name):
    entries = []
    for condition, package, services in [
        ("acpi_platform", "acpi", ["power_profile"]),
        ("heimdal", "kerberos", ["ipropd_master", "ipropd_slave", "kadmind", "kdc", "kfd", "kpasswdd"]),
        ("mit", "kerberos-kdc", ["kadmind", "kdc"]),
        ("ktls_services", "rc", ["tlsclntd", "tlsservd"]),
    ]:
        selected = []
        for service in services:
            target = name + "_" + condition + "_" + service
            bsd_install_file(name = target, src = service, destination = "/etc/rc.d/" + service,
                owner = "root", group = "wheel", mode = "0555", install_tags = ["package=" + package, "config"])
            selected.append(":" + target)
        entries = entries + select({":" + condition: selected, "//conditions:default": []})
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])

def service_directories():
    """Directory policy shared by rc.d and recursive rc installation."""
    return {"/etc/rc.d": '{"owner":"root","group":"wheel","mode":"0755","tags":["package=utilities"]}'} | select({
        "//libexec/rc/rc.d:heimdal": {"/var/heimdal": '{"owner":"root","group":"wheel","mode":"0700","tags":["package=utilities"]}'},
        "//conditions:default": {},
    })
