# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":pmc_shared",
        binary_name = name + "/libpmc.so.5", debug_name = name + "/libpmc.so.5.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libpmc.so.5",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libpmc.a", ["package=pmc", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libpmc.so.5", ["package=pmc"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libpmc.so.5.debug", ["package=pmc", "dbg"]),
    ]
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=pmc-man"], "//conditions:default": ["package=pmc-dev"]})
    for manual in ['pmc.3', 'pmc_allocate.3', 'pmc_attach.3', 'pmc_capabilities.3', 'pmc_configure_logfile.3', 'pmc_disable.3', 'pmc_event_names_of_class.3', 'pmc_get_driver_stats.3', 'pmc_get_msr.3', 'pmc_init.3', 'pmc_name_of_capability.3', 'pmc_read.3', 'pmc_set.3', 'pmc_start.3', 'pmclog.3', 'pmc.soft.3', 'pmc.amd.3', 'pmc.atom.3', 'pmc.atomsilvermont.3', 'pmc.cmn-600.3', 'pmc.core.3', 'pmc.core2.3', 'pmc.corei7.3', 'pmc.corei7uc.3', 'pmc.dmc-620.3', 'pmc.haswell.3', 'pmc.haswelluc.3', 'pmc.haswellxeon.3', 'pmc.iaf.3', 'pmc.ibs.3', 'pmc.ivybridge.3', 'pmc.ivybridgexeon.3', 'pmc.perf.3', 'pmc.rapl.3', 'pmc.sandybridge.3', 'pmc.sandybridgeuc.3', 'pmc.sandybridgexeon.3', 'pmc.tsc.3', 'pmc.ucf.3', 'pmc.westmere.3', 'pmc.westmereuc.3']:
        target = name + "_manual_" + manual
        bsd_compress(name = target, src = manual, output = name + "/" + manual + ".gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        files.append((":" + target, "/usr/share/man/man3/" + manual + ".gz", man_tags))
    for header in ["pmc.h", "pmclog.h", "pmcformat.h"]:
        files.append((header, "/usr/include/" + header, ["package=pmc", "dev"]))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libpmc.so", target = "libpmc.so.5",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=pmc", "dev"])
    for source, alias in [('pmc_allocate.3', 'pmc_release.3'), ('pmc_attach.3', 'pmc_detach.3'), ('pmc_capabilities.3', 'pmc_ncpu.3'), ('pmc_capabilities.3', 'pmc_npmc.3'), ('pmc_capabilities.3', 'pmc_pmcinfo.3'), ('pmc_capabilities.3', 'pmc_cpuinfo.3'), ('pmc_capabilities.3', 'pmc_width.3'), ('pmc_configure_logfile.3', 'pmc_flush_logfile.3'), ('pmc_configure_logfile.3', 'pmc_writelog.3'), ('pmc_disable.3', 'pmc_enable.3'), ('pmc_name_of_capability.3', 'pmc_name_of_class.3'), ('pmc_name_of_capability.3', 'pmc_name_of_cputype.3'), ('pmc_name_of_capability.3', 'pmc_name_of_disposition.3'), ('pmc_name_of_capability.3', 'pmc_name_of_event.3'), ('pmc_name_of_capability.3', 'pmc_name_of_mode.3'), ('pmc_name_of_capability.3', 'pmc_name_of_state.3'), ('pmc_read.3', 'pmc_rw.3'), ('pmc_read.3', 'pmc_write.3'), ('pmc_start.3', 'pmc_stop.3'), ('pmclog.3', 'pmclog_open.3'), ('pmclog.3', 'pmclog_close.3'), ('pmclog.3', 'pmclog_feed.3'), ('pmclog.3', 'pmclog_read.3'), ('pmc.amd.3', 'pmc.k8.3')]:
        target = name + "_alias_" + alias
        bsd_install_link(name = target, destination = "/usr/share/man/man3/" + alias + ".gz", target = "/usr/share/man/man3/" + source + ".gz", kind = "hardlink", owner = "root", group = "wheel", mode = "0444", install_tags = man_tags)
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
