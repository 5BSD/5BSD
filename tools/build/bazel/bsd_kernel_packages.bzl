# SPDX-License-Identifier: BSD-2-Clause
"""Project typed kernel installation into kernel-flavored and world pkgbase owners."""
load(":bsd_install.bzl", "BsdInstallManifestInfo", "resolve_hardlinks")
load(":bsd_install_archive.bzl", "BsdInstallArchiveInfo", "BsdInstallArchiveSetInfo")
load(":bsd_pkg_family.bzl", "bsd_pkg_family", "bsd_pkg_family_set")
load(":bsd_world_package_inventory.bzl", "bsd_world_package_inventory")
load(":bsd_world_package_reconciliation.bzl", "bsd_world_package_reconciliation")
load(":bsd_world_pkg_create.bzl", "bsd_world_pkg_create")
load(":bsd_world_pkg_solver_test.bzl", "bsd_world_pkg_solver_test")

def _project(ctx):
    info = ctx.attr.installation[BsdInstallArchiveInfo]
    if info.trees:
        fail("kernel package projection requires explicit installation records")
    kernconf = ctx.file.configuration.basename
    if kernconf != ctx.attr.kernconf:
        fail("kernel package configuration differs from its declared source filename")
    records = []
    for record in info.records:
        owners = [tag[8:] for tag in record["tags"] if tag.startswith("package=")]
        if len(owners) != 1 or not owners[0]:
            fail("one explicit package owner required in kernel installation")
        if owners[0] == "dtb":
            fail("DTB package composition requires its separate declared package path")
        is_kernel = owners[0] == "kernel"
        if is_kernel != (ctx.attr.kind == "kernel"):
            continue
        if is_kernel:
            record = dict(record, tags = ["package=kernel-" + kernconf.lower() if tag == "package=kernel" else tag for tag in record["tags"]])
        records.append(record)
    paths = {record["destination"]: record for record in records}
    if len(paths) != len(records):
        fail("duplicate kernel package installation destination")
    roots = resolve_hardlinks(paths)
    files = {file.path: file for file in info.payload.to_list()}
    selected = {}
    for record in records:
        if record["type"] in ["file", "hardlink"]:
            source = paths[roots[record["destination"]]]["source"]
            if source not in files:
                fail("kernel package record lacks its declared payload File: " + source)
            selected[source] = files[source]
    output = ctx.actions.declare_file(ctx.label.name + ".json")
    ctx.actions.write(output, json.encode(dict(format = 1, kind = ctx.attr.kind,
        kernconf = kernconf, configuration = ctx.file.configuration.path, files = records)) + "\n")
    payload = depset(selected.values())
    return [DefaultInfo(files = depset([output])), OutputGroupInfo(metadata = depset([output]),
            directory_metadata = depset([info.directory_metadata])),
        BsdInstallManifestInfo(manifest = output, records = records, payload = payload),
        BsdInstallArchiveSetInfo(records = records, payload = payload, trees = [],
            directory_metadata = depset([info.directory_metadata]))]

bsd_kernel_package_installation = rule(implementation = _project, attrs = {
    "installation": attr.label(providers = [BsdInstallArchiveInfo], mandatory = True),
    "configuration": attr.label(allow_single_file = True, mandatory = True),
    "kernconf": attr.string(mandatory = True),
    "kind": attr.string(mandatory = True, values = ["kernel", "world"]),
}, doc = "Retain actual payload Files and physical directory policy, projecting only package ownership.")

def kernel_pkgbase(name, installation, configuration):
    # The selected source file is the kernel configuration name, as KERNCONF in
    # Make. The projection checks the actual File basename before exposing data.
    kernconf = Label(configuration).name
    if not kernconf or "/" in kernconf or any([c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in kernconf.elems()]):
        fail("explicit kernel configuration source filename required")
    bsd_kernel_package_installation(name = name + "_installation", installation = installation,
        configuration = configuration, kernconf = kernconf, kind = "kernel", visibility = ["//visibility:public"])
    bsd_kernel_package_installation(name = name + "_world_modules", installation = installation,
        configuration = configuration, kernconf = kernconf, kind = "world", visibility = ["//visibility:public"])
    bsd_pkg_family(name = name + "_family", family = "kernel-" + kernconf.lower(),
        generator_family = "kernel", flavor_variable = "KERNEL_FLAVOR",
        template = "//release/packages:ucl/kernel-all.ucl", subpackages = ["dbg"],
        debug_files = "//tools/build/bazel/config:kernel_debug", sets = ["kernels"],
        ucl_variables = {"KERNEL_NAME": kernconf}, visibility = ["//visibility:public"])
    bsd_pkg_family_set(name = name + "_families", families = [":" + name + "_family"], visibility = ["//visibility:public"])
    bsd_world_package_inventory(name = name + "_inventory", archives = [":" + name + "_installation"],
        construction = [], suffix_tags = ["dbg"], visibility = ["//visibility:public"])
    bsd_world_package_reconciliation(name = name + "_reconciliation", inventory = ":" + name + "_inventory",
        families = ":" + name + "_families", visibility = ["//visibility:public"])
    bsd_world_pkg_create(name = name, families = ":" + name + "_families", archives = ":" + name + "_installation",
        inventory = ":" + name + "_inventory", reconciliation = ":" + name + "_reconciliation",
        abi_file = "//usr.bin/uname:uname", suffix_tags = ["dbg"], visibility = ["//visibility:public"])
    bsd_world_pkg_solver_test(name = name + "_solver_test", packages = ":" + name,
        families = ":" + name + "_families", abi_file = "//usr.bin/uname:uname", size = "large",
        visibility = ["//visibility:public"])
