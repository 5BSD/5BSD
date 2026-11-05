# SPDX-License-Identifier: BSD-2-Clause
"""Installation transformations for single-name utilities with optional sectioned manuals."""
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

def utility_debug_directories(package, bindir):
    """Original split-debug ancestors derived from the installation directory.

    Return archive directory policy without duplicating package-owned ancestors
    in the manifest. The debug root itself belongs to the base mtree policy.
    """
    if not bindir.startswith("/") or bindir.endswith("/") or any([p in ["", ".", ".."] for p in bindir[1:].split("/")]):
        fail("bindir must be a canonical absolute installation directory")
    result = {}
    current = "/usr/lib/debug"
    for component in bindir[1:].split("/"):
        current += "/" + component
        result[current] = json.encode({"owner": "root", "group": "wheel", "mode": "0755", "tags": ["package=" + package, "dbg"]})
    return result

def utility_installation(name, program, manual, package, bindir = "/usr/bin", man_section = "1", aliases = [], manual_aliases = [], extra_entries = [], binary_owner = "root", binary_group = "wheel", binary_mode = "0555", binary = None, keep_sections = [], binary_flags = ""):
    """Install program under its maintained name, optionally from a variant label.

    binary changes only the declared source artifact; installed/debug filenames
    and metadata still come from program. Other callers retain :program.
    keep_sections preserves explicitly declared non-allocated payloads while
    stripping, for example CAPIMAGE_MANIFEST signing input in .5bsd.policy.
    """
    if man_section not in ["1", "2", "3", "4", "5", "6", "7", "8", "9"]:
        fail("man_section must be a manual section from 1 through 9")
    if not bindir.startswith("/") or bindir.endswith("/") or ".." in bindir.split("/"):
        fail("bindir must be an absolute installation directory without trailing slash or parent traversal")
    bsd_debug_split(name = name + "_debug", src = binary if binary != None else ":" + program,
        binary_name = name + "/" + program, debug_name = name + "/" + program + ".debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/" + program,
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs", keep_sections = keep_sections)
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    if manual:
        bsd_compress(name = name + "_manual", src = manual, output = name + "/" + program + "." + man_section + ".gz",
            arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect",
            runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=" + package + "-man"],
        "//conditions:default": ["package=" + package]})
    # Extra package-owned entries share this manifest so hardlinks can resolve
    # against the utility payload (including aliases in other directories).
    # Keep configurable extra entries unresolved until the manifest rule.
    entries = []
    files = [
        ("binary", ":" + name + "_stripped", bindir + "/" + program, binary_mode, ["package=" + package]),
        ("symbols_file", ":" + name + "_symbols", "/usr/lib/debug" + bindir + "/" + program + ".debug", "0444", ["package=" + package, "dbg"]),
    ]
    if manual:
        files.append(("manual_file", ":" + name + "_manual", "/usr/share/man/man" + man_section + "/" + program + "." + man_section + ".gz", "0444", man_tags))
    for suffix, source, destination, mode, tags in files:
        target = name + "_" + suffix
        bsd_install_file(name = target, src = source, destination = destination, owner = binary_owner if suffix != "manual_file" else "root",
            group = binary_group if suffix != "manual_file" else "wheel", mode = mode, flags = binary_flags if suffix == "binary" else "", install_tags = tags)
        entries.append(":" + target)
    if len(depset(aliases).to_list()) != len(aliases):
        fail("duplicate utility alias")
    for alias in aliases:
        if not alias or alias in [".", "..", program] or "/" in alias:
            fail("utility alias must be a distinct basename")
        # Stable generated target names also support the test(1) alias '['.
        index = str(aliases.index(alias))
        binary = name + "_alias_" + index
        bsd_install_link(name = binary, destination = bindir + "/" + alias,
            target = bindir + "/" + program, kind = "hardlink", owner = binary_owner, group = binary_group,
            mode = binary_mode, install_tags = ["package=" + package])
        entries.append(":" + binary)
    all_manual_aliases = aliases + manual_aliases
    if len(depset(all_manual_aliases).to_list()) != len(all_manual_aliases):
        fail("duplicate utility manual alias")
    if all_manual_aliases and not manual:
        fail("manual aliases require a manual")
    for alias in all_manual_aliases:
        if not alias or alias in [".", "..", program] or "/" in alias:
            fail("manual alias must be a distinct basename")
        manual_alias = name + "_manual_alias_" + str(all_manual_aliases.index(alias))
        bsd_install_link(name = manual_alias,
            destination = "/usr/share/man/man" + man_section + "/" + alias + "." + man_section + ".gz",
            target = "/usr/share/man/man" + man_section + "/" + program + "." + man_section + ".gz",
            kind = "hardlink", owner = "root", group = "wheel", mode = "0444", install_tags = man_tags)
        entries.append(":" + manual_alias)
    bsd_install_manifest(name = name, entries = entries + extra_entries, visibility = ["//visibility:public"])
