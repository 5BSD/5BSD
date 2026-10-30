# SPDX-License-Identifier: BSD-2-Clause

load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

def _manpath(name):
    return "/usr/share/man/man" + name.rsplit(".", 1)[1] + "/" + name + ".gz"

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":bluetooth_shared",
        binary_name = name + "/libbluetooth.so.4", debug_name = name + "/libbluetooth.so.4.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libbluetooth.so.4",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libbluetooth.a", ["package=bluetooth", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libbluetooth.so.4", ["package=bluetooth", "lib"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libbluetooth.so.4.debug", ["package=bluetooth", "dbg"]),
    ]
    for header in ['bluetooth.h']:
        files.append((header, "/usr/include/" + header, ["package=bluetooth", "dev"]))
    for manual in ['bluetooth.3']:
        target = name + "_manual_" + manual
        bsd_compress(name = target, src = manual,
            output = name + "/" + manual + ".gz", arguments = ["-cn"],
            compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect",
            runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=bluetooth-man"],
            "//conditions:default": ["package=bluetooth-dev"]})
        files.append((":" + target, _manpath(manual), tags))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    for original, alias in [('bluetooth.3', 'bt_gethostbyname.3'), ('bluetooth.3', 'bt_gethostbyaddr.3'), ('bluetooth.3', 'bt_gethostent.3'), ('bluetooth.3', 'bt_sethostent.3'), ('bluetooth.3', 'bt_endhostent.3'), ('bluetooth.3', 'bt_getprotobyname.3'), ('bluetooth.3', 'bt_getprotobynumber.3'), ('bluetooth.3', 'bt_getprotoent.3'), ('bluetooth.3', 'bt_setprotoent.3'), ('bluetooth.3', 'bt_endprotoent.3'), ('bluetooth.3', 'bt_ntoa.3'), ('bluetooth.3', 'bt_aton.3'), ('bluetooth.3', 'bt_devaddr.3'), ('bluetooth.3', 'bt_devname.3'), ('bluetooth.3', 'bt_devinfo.3'), ('bluetooth.3', 'bt_devenum.3'), ('bluetooth.3', 'bt_devopen.3'), ('bluetooth.3', 'bt_devclose.3'), ('bluetooth.3', 'bt_devsend.3'), ('bluetooth.3', 'bt_devreq.3'), ('bluetooth.3', 'bt_devreq_events.3'), ('bluetooth.3', 'bt_devfilter.3'), ('bluetooth.3', 'bt_devfilter_pkt_set.3'), ('bluetooth.3', 'bt_devfilter_pkt_clr.3'), ('bluetooth.3', 'bt_devfilter_pkt_tst.3'), ('bluetooth.3', 'bt_devfilter_evt_set.3'), ('bluetooth.3', 'bt_devfilter_evt_clr.3'), ('bluetooth.3', 'bt_devfilter_evt_tst.3'), ('bluetooth.3', 'bt_devinquiry.3'), ('bluetooth.3', 'bdaddr_same.3'), ('bluetooth.3', 'bdaddr_any.3'), ('bluetooth.3', 'bdaddr_copy.3')]:
        target = name + "_alias_" + alias
        bsd_install_link(name = target, destination = _manpath(alias), target = _manpath(original),
            kind = "hardlink", owner = "root", group = "wheel", mode = "0444",
            install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=bluetooth-man"],
                "//conditions:default": ["package=bluetooth-dev"]}))
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libbluetooth.so", target = "libbluetooth.so.4",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=bluetooth", "dev"])
    for filename, mode in [("hosts", "0644"), ("protocols", "0444")]:
        target = name + "_configuration_" + filename
        bsd_install_file(name = target, src = filename, destination = "/etc/bluetooth/" + filename,
            owner = "root", group = "wheel", mode = mode, install_tags = ["package=bluetooth", "config"])
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
