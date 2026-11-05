# SPDX-License-Identifier: BSD-2-Clause
"""Original rescue installation policy: one ELF, hardlinks and DHCP script."""
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_strip_binary")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_directory", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")
load("//tools/build/bazel:bsd_sed_output.bzl", "bsd_sed_output")
load(":catalog.bzl", "ALIASES", "PROGRAMS")
load(":selection.bzl", "selected_program_lists")

# bsd.crunchgen.mk installs program names/aliases except these login argv names.
_SUPPRESSED_LINKS = ["-sh", "-csh", "-tcsh"]

def rescue_installation(name, binary):
    # Original bsd.crunchgen.mk explicitly sets MK_DEBUG_FILES=no.
    bsd_strip_binary(name = name + "_stripped", src = binary, output = name + "/rescue",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    bsd_install_file(name = name + "_binary", src = ":" + name + "_stripped",
        destination = "/rescue/rescue", owner = "root", group = "wheel", mode = "0555", install_tags = ["package=rescue"])
    bsd_install_directory(name = name + "_directory", destination = "/rescue",
        owner = "root", group = "wheel", mode = "0755", install_tags = ["package=rescue"])
    by_program = {}
    for program in PROGRAMS:
        entries = []
        names = [program] + [alias for alias in ALIASES.get(program, []) if alias not in _SUPPRESSED_LINKS and alias != "ping6"]
        for index, alias in enumerate(names):
            target = name + "_link_" + program + "_" + str(index)
            bsd_install_link(name = target, destination = "/rescue/" + alias, target = "/rescue/rescue",
                kind = "hardlink", owner = "root", group = "wheel", mode = "0555", install_tags = ["package=rescue"])
            entries.append(":" + target)
        by_program[program] = entries
    bsd_install_link(name = name + "_ping6", destination = "/rescue/ping6", target = "/rescue/rescue",
        kind = "hardlink", owner = "root", group = "wheel", mode = "0555", install_tags = ["package=rescue"])
    # Preserve the actual one-line sed recipe. No body/path rewriting is invented.
    bsd_sed_output(name = name + "_dhclient", template = "//sbin/dhclient:dhclient-script",
        output = "dhclient_FIXED", arguments = ["1s/\\/bin\\//\\/rescue\\//"],
        sed = "@bsd_sdk//toolchain:sed", runtime = ["@bsd_sdk//toolchain:sed_runtime"],
        redirect = "@bsd_sdk//toolchain:stdout_redirect")
    bsd_install_file(name = name + "_dhclient_file", src = ":" + name + "_dhclient",
        destination = "/rescue/dhclient-script", owner = "root", group = "wheel", mode = "0555", install_tags = ["package=rescue"])
    bsd_install_manifest(name = name,
        entries = [":" + name + "_directory", ":" + name + "_binary", ":" + name + "_dhclient_file"] + selected_program_lists(by_program) +
            select({"//rescue/rescue:installed_ping6": [":" + name + "_ping6"], "//conditions:default": []}),
        visibility = ["//visibility:public"])
