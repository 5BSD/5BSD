# SPDX-License-Identifier: BSD-2-Clause
"""Shared base installation conventions; component BUILD files own membership."""
load(":bsd_install.bzl", "bsd_install_file", "bsd_install_manifest")

def _program_install(name, visibility, binary, debug, destination, package, owner, group, mode, debug_mode, debug_root, extra_entries):
    if not destination.startswith("/") or destination.endswith("/"):
        fail("program destination must be an absolute file path")
    if not package or "," in package or "=" in package:
        fail("one explicit package name required")
    native.filegroup(
        name = name + "_debug_artifact",
        srcs = [debug],
        output_group = "debug_files",
    )
    bsd_install_file(
        name = name + "_binary",
        src = binary,
        destination = destination,
        owner = owner,
        group = group,
        mode = mode,
        install_tags = ["package=" + package],
    )
    bsd_install_file(
        name = name + "_debug",
        src = ":" + name + "_debug_artifact",
        destination = debug_root + destination + ".debug",
        owner = owner,
        group = group,
        mode = debug_mode,
        install_tags = ["dbg", "package=" + package],
    )
    bsd_install_manifest(
        name = name,
        entries = [":" + name + "_binary", ":" + name + "_debug"] + extra_entries,
        visibility = visibility,
    )

bsd_program_install = macro(
    implementation = _program_install,
    attrs = {
        "extra_entries": attr.label_list(),
        "binary": attr.label(mandatory = True, configurable = False),
        "debug": attr.label(mandatory = True, configurable = False),
        "destination": attr.string(mandatory = True, configurable = False),
        "package": attr.string(mandatory = True, configurable = False),
        "owner": attr.string(default = "root"),
        "group": attr.string(default = "wheel"),
        "mode": attr.string(default = "0555"),
        "debug_mode": attr.string(default = "0444"),
        "debug_root": attr.string(default = "/usr/lib/debug", configurable = False),
    },
)
