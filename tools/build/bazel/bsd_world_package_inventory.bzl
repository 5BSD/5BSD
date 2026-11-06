# SPDX-License-Identifier: BSD-2-Clause
"""Inventory static records and declared execution-expanded installation trees."""
load(":bsd_install.bzl", "BsdInstallManifestInfo")
load(":bsd_install_archive.bzl", "BsdInstallArchiveInfo", "BsdInstallArchiveSetInfo")

def _inventory(ctx):
    records, construction, trees, metadata, directory_metadata = [], [], [], [], []
    for target in ctx.attr.construction:
        construction.extend(target[BsdInstallManifestInfo].records)
    for target in ctx.attr.archives:
        info = target[BsdInstallArchiveInfo] if BsdInstallArchiveInfo in target else target[BsdInstallArchiveSetInfo]
        records.extend(info.records)
        directory_metadata.extend([info.directory_metadata] if BsdInstallArchiveInfo in target else info.directory_metadata.to_list())
        for tree in info.trees:
            trees.append(dict(prefix = tree.prefix, metadata = tree.metadata.path))
            metadata.append(tree.metadata)
    request = ctx.actions.declare_file(ctx.label.name + ".inputs.json")
    output = ctx.actions.declare_file(ctx.label.name + ".json")
    ctx.actions.write(request, json.encode(dict(format = 1, records = records,
        construction = construction, trees = trees, directory_metadata = [file.path for file in directory_metadata], suffix_tags = ctx.attr.suffix_tags)) + "\n")
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = ["-B", "-S", ctx.file._driver.path, request.path, output.path],
        inputs = [request, ctx.file._driver, ctx.file.python_home] + metadata + directory_metadata,
        tools = ctx.files.runtime, outputs = [output],
        env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1", "LC_ALL": "C"},
        use_default_shell_env = False, mnemonic = "BSDWorldPackageInventory")
    return [DefaultInfo(files = depset([output])), OutputGroupInfo(metadata = depset([output]))]

bsd_world_package_inventory = rule(implementation = _inventory, attrs = {
    "archives": attr.label_list(providers = [[BsdInstallArchiveInfo], [BsdInstallArchiveSetInfo]], mandatory = True),
    "construction": attr.label_list(providers = [BsdInstallManifestInfo], mandatory = True),
    "suffix_tags": attr.string_list(mandatory = True),
    "python": attr.label(default = "@bsd_sdk//toolchain:extra_python", executable = True, allow_single_file = True, cfg = "exec"),
    "python_home": attr.label(default = "@bsd_sdk//toolchain:python-home/runtime.json", allow_single_file = True, cfg = "exec"),
    "runtime": attr.label_list(default = ["@bsd_sdk//toolchain:python_stdlib"], allow_files = True, cfg = "exec"),
    "_driver": attr.label(default = Label(":world_package_inventory.py"), allow_single_file = True),
}, doc = "Partition complete world metadata, including generated trees; package creation is a separate gate.")
