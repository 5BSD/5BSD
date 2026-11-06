# SPDX-License-Identifier: BSD-2-Clause
"""Complete distrib-dirs policy from source mtree specifications and selected owners."""
load(":bsd_install_archive.bzl", "BsdInstallArchiveInfo")
load(":bsd_pkg_family.bzl", "BsdPackageFamilySetInfo")

BsdMtreeSpecInfo = provider(fields = ["source", "prefixes"])

def _spec(ctx):
    if not ctx.attr.prefixes or any([not p.startswith("/") or ".." in p.split("/") for p in ctx.attr.prefixes]):
        fail("explicit absolute mtree prefixes required")
    return [BsdMtreeSpecInfo(source = ctx.file.src, prefixes = ctx.attr.prefixes), DefaultInfo(files = depset([ctx.file.src]))]

bsd_mtree_spec = rule(implementation = _spec, attrs = {
    "src": attr.label(allow_single_file = True, mandatory = True),
    "prefixes": attr.string_list(mandatory = True),
})

def _layout(ctx):
    specs, files = [], []
    for target in ctx.attr.specs:
        info = target[BsdMtreeSpecInfo]
        files.append(info.source)
        specs.extend([dict(source = info.source.path, prefix = prefix) for prefix in info.prefixes])
    catalogue = ctx.attr.families[BsdPackageFamilySetInfo].catalogue
    request = ctx.actions.declare_file(ctx.label.name + ".inputs.json")
    archive = ctx.actions.declare_file(ctx.label.name + ".tar")
    metadata = ctx.actions.declare_file(ctx.label.name + ".directories.json")
    report = ctx.actions.declare_file(ctx.label.name + ".policy.json")
    ctx.actions.write(request, json.encode(dict(specs = specs, catalogue = catalogue.path,
        passwd = ctx.file.passwd.path, group = ctx.file.group.path, mtree = ctx.executable.mtree.path,
        epoch = ctx.attr.epoch, suffix_tags = ctx.attr.suffix_tags, archive = archive.path, metadata = metadata.path, report = report.path)) + "\n")
    runtime_dirs = {f.dirname: True for f in ctx.files.mtree_runtime}
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = ["-B", "-S", ctx.file._driver.path, request.path],
        inputs = files + [request, catalogue, ctx.file.passwd, ctx.file.group, ctx.file.python_home, ctx.file._driver] + ctx.files._modules,
        tools = [ctx.attr.mtree[DefaultInfo].files_to_run] + ctx.files.runtime + ctx.files.mtree_runtime,
        outputs = [archive, metadata, report], use_default_shell_env = False,
        env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1", "LC_ALL": "C", "LD_LIBRARY_PATH": ":".join(runtime_dirs)},
        mnemonic = "BSDWorldDirectoryLayout")
    return [DefaultInfo(files = depset([archive])), OutputGroupInfo(metadata = depset([report]), directory_metadata = depset([metadata])),
        BsdInstallArchiveInfo(directory_metadata = metadata, records = [], payload = depset(), trees = [])]

bsd_world_layout = rule(implementation = _layout, attrs = {
    "specs": attr.label_list(providers = [BsdMtreeSpecInfo], mandatory = True),
    "families": attr.label(providers = [BsdPackageFamilySetInfo], mandatory = True),
    "passwd": attr.label(default = Label("//etc:master.passwd"), allow_single_file = True),
    "group": attr.label(default = Label("//etc:group"), allow_single_file = True),
    "epoch": attr.int(default = 0),
    "suffix_tags": attr.string_list(mandatory = True),
    "mtree": attr.label(default = "@bsd_sdk//toolchain:extra_mtree", executable = True, allow_single_file = True, cfg = "exec"),
    "python": attr.label(default = "@bsd_sdk//toolchain:extra_python", executable = True, allow_single_file = True, cfg = "exec"),
    "python_home": attr.label(default = "@bsd_sdk//toolchain:python-home/runtime.json", allow_single_file = True, cfg = "exec"),
    "runtime": attr.label_list(default = ["@bsd_sdk//toolchain:python_stdlib"], allow_files = True, cfg = "exec"),
    "mtree_runtime": attr.label_list(default = ["@bsd_sdk//toolchain:extra_mtree_runtime"], allow_files = True, cfg = "exec"),
    "_driver": attr.label(default = Label(":world_layout.py"), allow_single_file = True),
    "_modules": attr.label_list(default = [Label(":directory_metadata.py"), Label(":archive_policy.py"), Label(":install_archive.py"), Label(":world_package_inventory.py")], allow_files = True),
})
