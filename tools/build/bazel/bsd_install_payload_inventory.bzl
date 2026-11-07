# SPDX-License-Identifier: BSD-2-Clause
"""Bind selected installed payload Files to execution paths and content digests."""
load(":bsd_install_archive.bzl", "BsdInstallArchiveInfo", "BsdInstallArchiveSetInfo")

def _inventory(ctx):
    info = ctx.attr.installation[BsdInstallArchiveInfo] if BsdInstallArchiveInfo in ctx.attr.installation else ctx.attr.installation[BsdInstallArchiveSetInfo]
    files = depset([tree.tree for tree in info.trees], transitive = [info.payload])
    output = ctx.actions.declare_file(ctx.label.name + ".json")
    args = ctx.actions.args()
    # Bazel expands declared TreeArtifacts into their members. No filesystem
    # walk, installed-tree inventory or repository-name substitution discovers inputs.
    args.add_all(files, expand_directories = True)
    args.use_param_file("@%s", use_always = True)
    args.set_param_file_format("multiline")
    ctx.actions.run(executable = ctx.attr._python[DefaultInfo].files_to_run,
        arguments = ["-B", "-S", ctx.file._runner.path, output.path, args],
        inputs = depset([ctx.file._runner, ctx.file._python_home] + ctx.files._runtime, transitive = [files]),
        outputs = [output], env = {"LC_ALL": "C", "PYTHONHOME": ctx.file._python_home.dirname,
            "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": "",
            "LD_LIBRARY_PATH": ":".join(sorted(depset([file.dirname for file in ctx.files._runtime]).to_list()))},
        use_default_shell_env = False, mnemonic = "BSDInstallPayloadInventory")
    return [DefaultInfo(files = depset([output])), OutputGroupInfo(metadata = depset([output]))]

bsd_install_payload_inventory = rule(implementation = _inventory, attrs = {
    "installation": attr.label(providers = [[BsdInstallArchiveInfo], [BsdInstallArchiveSetInfo]], mandatory = True),
    "_runner": attr.label(default = Label(":payload_inventory.py"), allow_single_file = True, cfg = "exec"),
    "_python": attr.label(default = "@bsd_sdk//toolchain:extra_python", executable = True, allow_single_file = True, cfg = "exec"),
    "_python_home": attr.label(default = "@bsd_sdk//toolchain:python-home/runtime.json", allow_single_file = True, cfg = "exec"),
    "_runtime": attr.label_list(default = ["@bsd_sdk//toolchain:python_stdlib"], allow_files = True, cfg = "exec"),
})
