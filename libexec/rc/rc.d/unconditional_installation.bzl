# SPDX-License-Identifier: BSD-2-Clause
"""Always-installed rc.d payload groups; conditional groups are separate."""
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest")

_GROUPS = {
    "CONFS": ("rc", ["DAEMON", "FILESYSTEMS", "LOGIN", "NETWORKING", "SERVERS", "adjkerntz", "backlight", "bgfsck", "bridge", "cfumass", "cleanvar", "cleartmp", "ddb", "defaultroute", "devfs", "dmesg", "dumpon", "fsck", "growfs", "growfs_fstab", "growfs_postboot", "hostid", "hostid_save", "hostname", "iovctl", "ip6addrctl", "ipsec", "kld", "kldxref", "ldconfig", "linux", "local", "localpkg", "motd", "mountcritlocal", "mountcritremote", "mountlate", "mdconfig", "mdconfig2", "msgs", "netif", "netoptions", "netwait", "noshutdown", "os-release", "pwcheck", "quota", "random", "rarpd", "rctl", "root", "routing", "rpcbind", "rtadvd", "rtsold", "savecore", "securelevel", "static_arp", "static_ndp", "swap", "swaplate", "sysctl", "sysctl_lastload", "sysvipc", "tmp", "var", "var_run", "watchdogd"]),
    "DEVD": ("devd", ["devd"]),
    "MAC_ABAC": ("mac-abac", ["mac_abacd"]),
    "DEVMATCH": ("devmatch", ["devmatch"]),
    "DHCLIENT": ("dhclient", ["dhclient"]),
    "CRON": ("cron", ["cron"]),
    "CTL": ("ctl", ["ctld"]),
    "GEOM": ("geom", ["geli", "geli2", "gptboot"]),
    "GGATED": ("ggate", ["ggated"]),
    "NEWSYSLOG": ("newsyslog", ["newsyslog"]),
    "NFS": ("nfs", ["lockd", "mountd", "nfscbd", "nfsclient", "nfsd", "nfsuserd", "statd"]),
    "POWERD": ("powerd", ["powerd"]),
    "PPPOED": ("ppp", ["pppoed"]),
    "SYSLOGD": ("syslogd", ["syslogd"]),
    "RESOLVCONF": ("resolvconf", ["resolv"]),
}

def unconditional_installation(name):
    entries = []
    for group, (package, services) in _GROUPS.items():
        for service in services:
            target = name + "_" + service
            bsd_install_file(name = target, src = service, destination = "/etc/rc.d/" + service,
                owner = "root", group = "wheel", mode = "0555", install_tags = ["package=" + package, "config"])
            entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
