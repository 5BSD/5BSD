# SPDX-License-Identifier: BSD-2-Clause
"""Cacheable installation archives; inode relationships are serialized metadata."""
load(":bsd_install.bzl", "BsdInstallManifestInfo")
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")

BsdInstallArchiveInfo = provider(fields = ["directory_metadata"])
# A collection preserves output groups but is not a single package archive.
BsdInstallArchiveSetInfo = provider(fields = [])

def _archive(ctx):
    epoch = ctx.attr.epoch
    if ctx.attr.epoch_setting:
        if epoch != -1:
            fail("select either an explicit archive epoch or a setting")
        value = ctx.attr.epoch_setting[BuildSettingInfo].value
        if type(value) != "string" or not value or any([c not in "0123456789" for c in value.elems()]):
            fail("archive epoch setting must be a nonnegative decimal string")
        epoch = int(value, 10)
    if epoch < 0:
        fail("explicit nonnegative archive epoch required")
    records, payloads = [], []
    runtime_names = []
    for library in ctx.files.mtree_runtime_libraries:
        if library.basename in runtime_names:
            fail("duplicate mtree runtime library basename: " + library.basename)
        runtime_names.append(library.basename)
    if ctx.files.mtree_runtime_libraries and not ctx.attr.mtree_specs:
        fail("mtree runtime libraries require mtree policy")
    for target in ctx.attr.manifests:
        info = target[BsdInstallManifestInfo]
        records.extend(info.records)
        payloads.append(info.payload)
    for path, value in ctx.attr.directories.items():
        record = json.decode(value)
        record.update(destination = path, type = "dir")
        records.append(record)
    request = ctx.actions.declare_file(ctx.label.name + ".json")
    archive = ctx.actions.declare_file(ctx.label.name + ".tar")
    directory_metadata = ctx.actions.declare_file(ctx.label.name + ".directories.json")
    policy_inputs = ctx.files.mtree_specs + ctx.files._policy_modules
    policy_tools = []
    specs = []
    if ctx.file.supplemental_mtree and not ctx.attr.mtree_specs:
        fail("supplemental mtree requires base mtree/account policy")
    if ctx.attr.mtree_specs:
        if not ctx.executable.mtree or not ctx.file.passwd or not ctx.file.group:
            fail("mtree policy requires explicit tool/account files")
        policy_inputs += [ctx.file.passwd, ctx.file.group]
        policy_tools = [ctx.attr.mtree[DefaultInfo].files_to_run]
        for target, prefix in ctx.attr.mtree_specs.items():
            files = target[DefaultInfo].files.to_list()
            if len(files) != 1:
                fail("one file per mtree specification required")
            specs.append(dict(source = files[0].path, prefix = prefix))
    if ctx.file.supplemental_mtree:
        policy_inputs.append(ctx.file.supplemental_mtree)
        specs.append(dict(source = ctx.file.supplemental_mtree.path, prefix = "/"))
    ctx.actions.write(request, json.encode(dict(
        records = records,
        users = {key: int(value) for key, value in ctx.attr.users.items()},
        groups = {key: int(value) for key, value in ctx.attr.groups.items()},
        epoch = epoch,
        mtree_specs = specs,
        directory_packages = ctx.attr.directory_packages,
        mtree = ctx.executable.mtree.path if ctx.executable.mtree else None,
        mtree_runtime_libraries = [file.path for file in ctx.files.mtree_runtime_libraries],
        passwd = ctx.file.passwd.path if ctx.file.passwd else None,
        group = ctx.file.group.path if ctx.file.group else None,
    )) + "\n")
    args = ctx.actions.args()
    args.add_all(["-B", "-S", ctx.file._writer.path, request.path, archive.path, "--directory-metadata", directory_metadata.path])
    ctx.actions.run(
        executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = [args],
        inputs = depset([request, ctx.file._writer, ctx.file.python_home] + policy_inputs, transitive = payloads),
        tools = ctx.files.runtime + ctx.files.mtree_runtime_libraries + policy_tools,
        outputs = [archive, directory_metadata],
        env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1", "LC_ALL": "C"},
        use_default_shell_env = False,
        mnemonic = "BSDInstallArchive",
    )
    return [DefaultInfo(files = depset([archive])), OutputGroupInfo(metadata = depset([request]), directory_metadata = depset([directory_metadata])), BsdInstallArchiveInfo(directory_metadata = directory_metadata)]

bsd_install_archive = rule(
    implementation = _archive,
    attrs = {
        "manifests": attr.label_list(providers = [BsdInstallManifestInfo], mandatory = True),
        "directories": attr.string_dict(),
        "directory_packages": attr.string_list(),
        "supplemental_mtree": attr.label(allow_single_file = True),
        "users": attr.string_dict(),
        "groups": attr.string_dict(),
        "mtree_specs": attr.label_keyed_string_dict(allow_files = True),
        "mtree": attr.label(executable = True, cfg = "exec", allow_single_file = True),
        "mtree_runtime_libraries": attr.label_list(cfg = "exec", allow_files = True, doc = "Declared DSOs for the mtree subprocess only."),
        "passwd": attr.label(allow_single_file = True),
        "group": attr.label(allow_single_file = True),
        "_policy_modules": attr.label_list(default = [Label(":archive_policy.py"), Label(":directory_metadata.py")], allow_files = True, cfg = "exec"),
        "epoch": attr.int(default = -1),
        "epoch_setting": attr.label(providers = [BuildSettingInfo]),
        "python": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "python_home": attr.label(cfg = "exec", allow_single_file = True, mandatory = True),
        "runtime": attr.label_list(cfg = "exec", allow_files = True),
        "_writer": attr.label(default = Label(":install_archive.py"), allow_single_file = True, cfg = "exec"),
    },
)

def _archive_set(ctx):
    return [
        BsdInstallArchiveSetInfo(),
        DefaultInfo(files = depset(transitive = [target[DefaultInfo].files for target in ctx.attr.archives])),
        OutputGroupInfo(
            metadata = depset(transitive = [target[OutputGroupInfo].metadata for target in ctx.attr.archives]),
            directory_metadata = depset(transitive = [target[OutputGroupInfo].directory_metadata for target in ctx.attr.archives]),
        ),
    ]

bsd_install_archive_set = rule(
    implementation = _archive_set,
    attrs = {"archives": attr.label_list(providers = [[BsdInstallArchiveInfo], [BsdInstallArchiveSetInfo]], mandatory = True)},
    doc = "Group declared archives or nested archive sets while preserving metadata output groups.",
)
