# SPDX-License-Identifier: BSD-2-Clause
"""Index declared installed manuals, preserving alias and hardlink semantics."""
load(":bsd_install_archive.bzl", "BsdInstallArchiveInfo", "BsdInstallArchiveSetInfo")
load(":bsd_install.bzl", "BsdInstallManifestInfo", "resolve_hardlinks")

def _database(ctx):
    root = ctx.attr.root
    if not root.startswith("/") or any([part in ["", ".", ".."] for part in root[1:].split("/")]):
        fail("manual root must be a canonical absolute directory")
    selected, files = {}, {}
    for target in ctx.attr.archives:
        info = target[BsdInstallArchiveInfo] if BsdInstallArchiveInfo in target else target[BsdInstallArchiveSetInfo]
        for expanded in info.trees:
            prefix = expanded.prefix.rstrip("/")
            if prefix == root or prefix.startswith(root + "/") or root.startswith(prefix + "/"):
                fail("manual corpus intersects execution-expanded tree " + prefix + "; declare an explicit supported manual inventory")
        for row in info.records:
            path = row["destination"]
            if row["type"] == "dir" or not path.startswith(root + "/"):
                continue
            if path == root + "/mandoc.db":
                fail("manual database cannot index itself")
            if path in selected:
                fail("duplicate installed manual: " + path)
            selected[path] = row
        for file in info.payload.to_list():
            files[file.path] = file
    hardlinks = resolve_hardlinks(selected)
    records = [selected[path] for path in sorted(selected)]
    payload = [files[row["source"]] for row in records if row["type"] == "file"]
    manifest = ctx.actions.declare_file(ctx.label.name + ".install.json")
    installed, outputs = [], []
    if records:
        request = ctx.actions.declare_file(ctx.label.name + ".inputs.json")
        output = ctx.actions.declare_file(ctx.label.name + "/mandoc.db")
        executable = ctx.actions.declare_file(ctx.label.name + ".tools/makewhatis")
        ctx.actions.symlink(output = executable, target_file = ctx.executable.makewhatis, is_executable = True)
        ctx.actions.write(request, json.encode(dict(root = root, records = records, hardlink_roots = hardlinks)) + "\n")
        ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
            arguments = ["-B", "-S", ctx.file._driver.path, request.path, executable.path, output.path],
            inputs = [request, ctx.file._driver, ctx.file.python_home, executable] + payload,
            tools = [ctx.attr.makewhatis[DefaultInfo].files_to_run] + ctx.files.runtime,
            outputs = [output], env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1", "LC_ALL": "C", "PATH": ""},
            use_default_shell_env = False, mnemonic = "BSDManualDatabase")
        outputs = [output]
        installed = [dict(destination = root + "/mandoc.db", source = output.path, type = "file",
            owner = "root", group = "wheel", mode = "0644", tags = [], flags = "")]
    ctx.actions.write(manifest, json.encode(dict(format = 1, files = installed)) + "\n")
    return [DefaultInfo(files = depset(outputs)),
        BsdInstallManifestInfo(manifest = manifest, payload = depset(outputs), records = installed),
        OutputGroupInfo(manifest = depset([manifest]))]

bsd_man_database = rule(implementation = _database, attrs = {
    "archives": attr.label_list(providers = [[BsdInstallArchiveInfo], [BsdInstallArchiveSetInfo]], mandatory = True),
    "root": attr.string(mandatory = True),
    "makewhatis": attr.label(default = "//usr.bin/mandoc:makewhatis_execution", executable = True, cfg = "exec"),
    "python": attr.label(default = "@bsd_sdk//toolchain:extra_python", executable = True, allow_single_file = True, cfg = "exec"),
    "python_home": attr.label(default = "@bsd_sdk//toolchain:python-home/runtime.json", allow_single_file = True, cfg = "exec"),
    "runtime": attr.label_list(default = ["@bsd_sdk//toolchain:python_stdlib"], allow_files = True, cfg = "exec"),
    "_driver": attr.label(default = Label(":generate_man_database.py"), allow_single_file = True),
})
