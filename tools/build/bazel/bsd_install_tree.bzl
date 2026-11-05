# SPDX-License-Identifier: BSD-2-Clause
"""Package a declared generated tree using Bazel's execution-time file expansion."""
load(":bsd_install_archive.bzl", "BsdInstallArchiveInfo")

def _archive(ctx):
    tree = ctx.file.tree
    if not tree.is_directory:
        fail("tree must be a declared directory artifact")
    if ctx.attr.epoch < 0:
        fail("explicit nonnegative archive epoch required")
    files = []
    for target, destination in ctx.attr.files.items():
        entries = target[DefaultInfo].files.to_list()
        if len(entries) != 1 or entries[0].is_directory:
            fail("each additional payload must identify one file")
        files.append(dict(source = entries[0].path, destination = destination))
    plan = ctx.actions.declare_file(ctx.label.name + ".plan.json")
    metadata = ctx.actions.declare_file(ctx.label.name + ".json")
    archive = ctx.actions.declare_file(ctx.label.name + ".tar")
    directories = ctx.actions.declare_file(ctx.label.name + ".directories.json")
    specs = []
    for target, prefix in ctx.attr.mtree_specs.items():
        entries = target[DefaultInfo].files.to_list()
        if len(entries) != 1 or entries[0].is_directory:
            fail("one file per mtree specification required")
        specs.append(dict(source = entries[0].path, prefix = prefix))
    ctx.actions.write(plan, json.encode(dict(format = 1, tree = tree.path,
        prefix = ctx.attr.prefix, files = files, extra_directories = ctx.attr.extra_directories,
        owner = ctx.attr.owner, group = ctx.attr.group, file_mode = ctx.attr.file_mode,
        directory_mode = ctx.attr.directory_mode, file_tags = ctx.attr.file_tags,
        directory_tags = ctx.attr.directory_tags,
        archive = dict(users = {}, groups = {}, records = [], epoch = ctx.attr.epoch,
            passwd = ctx.file.passwd.path, group = ctx.file.group_file.path,
            mtree = ctx.executable.mtree.path, mtree_runtime_libraries = [f.path for f in ctx.files.mtree_runtime_libraries],
            directory_packages = ctx.attr.directory_packages,
            mtree_specs = specs))))
    # Python must see its script before the response file; expand the tool's
    # own argument file in the serializer, rather than in the interpreter.
    command = ctx.actions.args()
    command.add_all(["-B", "-S", ctx.file._writer.path])
    payload = ctx.actions.args()
    payload.add_all(["--plan", plan.path, "--metadata", metadata.path,
        "--archive", archive.path, "--directories", directories.path])
    payload.add_all([tree], before_each = "--tree-file", expand_directories = True)
    payload.use_param_file("@%s", use_always = True)
    payload.set_param_file_format("multiline")
    inputs = [plan, tree, ctx.file._writer, ctx.file.python_home, ctx.file.passwd, ctx.file.group_file]
    inputs += ctx.files.files + ctx.files.mtree_specs + ctx.files._modules
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = [command, payload], inputs = inputs,
        tools = ctx.files.runtime + ctx.files.mtree_runtime_libraries + [ctx.attr.mtree[DefaultInfo].files_to_run],
        outputs = [metadata, archive, directories], use_default_shell_env = False,
        env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1", "LC_ALL": "C"},
        mnemonic = "BSDInstallTreeArchive")
    return [DefaultInfo(files = depset([archive])),
        OutputGroupInfo(metadata = depset([metadata]), directory_metadata = depset([directories])),
        BsdInstallArchiveInfo(directory_metadata = directories, records = [],
            payload = depset([tree] + ctx.files.files),
            trees = [struct(prefix = ctx.attr.prefix, tree = tree, metadata = metadata)])]

bsd_install_tree_archive = rule(implementation = _archive, attrs = {
    "tree": attr.label(allow_single_file = True, mandatory = True),
    "files": attr.label_keyed_string_dict(allow_files = True),
    "prefix": attr.string(mandatory = True),
    "extra_directories": attr.string_list(),
    "owner": attr.string(mandatory = True), "group": attr.string(mandatory = True),
    "file_mode": attr.string(mandatory = True), "directory_mode": attr.string(mandatory = True),
    "file_tags": attr.string_list(mandatory = True), "directory_tags": attr.string_list(),
    "directory_packages": attr.string_list(), "epoch": attr.int(mandatory = True),
    "passwd": attr.label(allow_single_file = True, mandatory = True),
    "group_file": attr.label(allow_single_file = True, mandatory = True),
    "mtree_specs": attr.label_keyed_string_dict(allow_files = True),
    "mtree_runtime_libraries": attr.label_list(allow_files = True, cfg = "exec"),
    "mtree": attr.label(allow_single_file = True, executable = True, cfg = "exec", mandatory = True),
    "python": attr.label(allow_single_file = True, executable = True, cfg = "exec", mandatory = True),
    "python_home": attr.label(allow_single_file = True, cfg = "exec", mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
    "_writer": attr.label(default = Label(":install_tree.py"), allow_single_file = True),
    "_modules": attr.label_list(default = [Label(":archive_policy.py"), Label(":directory_metadata.py"), Label(":install_archive.py")], allow_files = True),
})
