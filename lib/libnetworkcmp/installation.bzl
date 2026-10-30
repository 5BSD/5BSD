# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

MANUAL_ALIASES = {
    "libnetworkcmp": ["networkcmp_hello", "networkcmp_connect", "networkcmp_connect_ex", "networkcmp_udp", "networkcmp_listen", "networkcmp_resolve", "networkcmp_getaddrinfo", "networkcmp_freeaddrinfo", "networkcmp_client_open", "networkcmp_client_limits", "networkcmp_client_close", "networkcmp_pf_open"],
    "network_state": ["network_state_open", "network_state_watch", "network_state_close"],
}

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":networkcmp_shared",
        binary_name = name + "/libnetworkcmp.so.1", debug_name = name + "/libnetworkcmp.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libnetworkcmp.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
                ("networkcmp.h", "/usr/include/networkcmp.h", ["package=libnetworkcmp", "dev"]),
        ("networkcmp_protocol.h", "/usr/include/networkcmp_protocol.h", ["package=libnetworkcmp", "dev"]),
        ("networkcmp_server.h", "/usr/include/networkcmp_server.h", ["package=libnetworkcmp", "dev"]),
        ("network_state.h", "/usr/include/network_state.h", ["package=libnetworkcmp", "dev"]),
        ("network_state_protocol.h", "/usr/include/network_state_protocol.h", ["package=libnetworkcmp", "dev"]),

        (":static_archive", "/usr/lib/libnetworkcmp.a", ["package=libnetworkcmp", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libnetworkcmp.so.1", ["package=libnetworkcmp"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libnetworkcmp.so.1.debug", ["package=libnetworkcmp", "dbg"]),
    ]
    for manual in MANUAL_ALIASES:
        bsd_compress(name = name + "_manual_" + manual, src = manual + ".3",
            output = name + "/" + manual + ".3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
            redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        files.append((":" + name + "_manual_" + manual, "/usr/share/man/man3/" + manual + ".3.gz",
            select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libnetworkcmp-man"], "//conditions:default": ["package=libnetworkcmp-dev"]})))
    files.append(("networkcmp.fidl", "/usr/share/fidl/networkcmp.fidl", ["package=libnetworkcmp-dev"]))
    files += [("//contrib/fuchsia:" + n, "/usr/share/licenses/libnetworkcmp/fuchsia/" + n, ["package=libnetworkcmp"]) for n in ["LICENSE", "PATENTS"]]
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libnetworkcmp.so", target = "libnetworkcmp.so.1",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=libnetworkcmp", "dev"])
    for manual in MANUAL_ALIASES:
        for alias in MANUAL_ALIASES[manual]:
            target = name + "_manual_" + alias
            bsd_install_link(name = target, destination = "/usr/share/man/man3/" + alias + ".3.gz",
                target = "/usr/share/man/man3/" + manual + ".3.gz", kind = "hardlink",
                owner = "root", group = "wheel", mode = "0444",
                install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libnetworkcmp-man"], "//conditions:default": ["package=libnetworkcmp-dev"]}))
            entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
