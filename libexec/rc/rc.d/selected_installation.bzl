# SPDX-License-Identifier: BSD-2-Clause
"""Service groups controlled by the shared native build settings."""
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest")
_GROUPS = {
    "audit": ("audit", "audit", ["auditd", "auditdistd"]),
    "autofs": ("autofs", "autofs", ["automount", "automountd", "autounmountd"]),
    "blocklist": ("blocklist", "blocklist", ["blacklistd", "blocklistd"]),
    "bluetooth": ("bluetooth", "bluetooth", ["blued", "bluetooth", "bthidd", "hcsecd", "meshd", "rfcomm_pppd_server", "sdpd", "ubthidhci"]),
    "bootparamd": ("bootparamd", "rc", ["bootparams"]),
    "bsnmp": ("bsnmp", "bsnmp", ["bsnmpd"]),
    "gssd": ("kerberos_support", "gssd", ["gssd"]),
    "hast": ("hast", "hast", ["hastd"]),
    "inetd": ("inetd", "inetd", ["inetd"]),
    "dummynet": ("dummynet", "dummynet", ["dnctl", "dummynet"]),
    "iscsi": ("iscsi", "iscsi", ["iscsictl", "iscsid"]),
    "jail": ("jail", "jail", ["jail"]),
    "lp": ("lpr", "lp", ["lpd"]),
    "nis": ("nis", "yp", ["ypbind", "ypldap", "yppasswdd", "ypserv", "ypset", "ypupdated", "ypxfrd", "nisdomain"]),
    "nscd": ("ns_caching", "rc", ["nscd"]),
    "ntp": ("ntp", "ntp", ["ntpd", "ntpdate"]),
    "nuageinit": ("nuageinit", "nuageinit", ["nuageinit", "nuageinit_post_net", "nuageinit_user_data_script"]),
    "opensm": ("ofed_extra", "rc", ["opensm"]),
    "pf": ("pf", "pf", ["pf", "pflog", "pfsync", "ftp-proxy", "tftpproxy"]),
    "ppp": ("ppp", "ppp", ["ppp"]),
    "sendmail": ("sendmail", "sendmail", ["sendmail"]),
    "ssh": ("openssh", "ssh", ["sshd"]),
    "unbound": ("unbound", "local-unbound", ["local_unbound"]),
    "vi": ("vi", "vi", ["virecover"]),
    "sound": ("sound", "sound", ["mixer", "virtual_oss"]),
    "hostapd": ("wireless", "hostapd", ["hostapd"]),
    "wpa": ("wireless", "wpa", ["wpa_supplicant"]),
    "zfs": ("zfs", "zfs", ["zfs", "zfsbe", "zfsd", "zfskeys", "zpool", "zpoolreguid", "zpoolupgrade", "zvol"]),
    "syscons": ("legacy_console", "console-tools", ["moused", "msconvd", "syscons"]),
    "accounting": ("acct", "acct", ["accounting"]),
    "utx": ("utmpx", "acct", ["utx"]),
}

def selected_installation(name):
    entries = []
    for group, (setting, package, services) in _GROUPS.items():
        group_entries = []
        for service in services:
            target = name + "_" + service
            bsd_install_file(name = target, src = service, destination = "/etc/rc.d/" + service,
                owner = "root", group = "wheel", mode = "0555", install_tags = ["package=" + package, "config"])
            group_entries.append(":" + target)
        entries = entries + select({"//tools/build/bazel/config:" + setting + "_enabled": group_entries, "//conditions:default": []})
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
