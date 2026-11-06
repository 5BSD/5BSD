# SPDX-License-Identifier: BSD-2-Clause
"""Declared linker.hints generation from typed installed ELF inputs."""
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load(":bsd_install.bzl", "BsdInstallFileInfo", "BsdInstallManifestInfo", "resolve_hardlinks")
load(":bsd_kernel_installation.bzl", "kernel_installation_directory")

BsdLinkerHintsInfo = provider(fields = ["output", "directory", "inputs", "aliases", "tool", "runtime", "plan"])

def _eligible(name):
    return "." not in name or name.endswith(".ko")

def _hints(ctx):
    installation = ctx.attr.installation[BsdInstallManifestInfo]
    directory = kernel_installation_directory(ctx.attr.directory[BuildSettingInfo].value)
    records = {record["destination"]: record for record in installation.records}
    roots = resolve_hardlinks(records)
    payload = {file.path: file for file in installation.payload.to_list()}
    selected, aliases = {}, {}
    for destination, record in records.items():
        parent, name = destination.rsplit("/", 1)
        if (parent or "/") != directory or not _eligible(name):
            continue
        if record["type"] == "symlink":
            aliases[name] = record["link"]
        elif record["type"] in ["file", "hardlink"]:
            source = records[roots[destination]]["source"]
            if source not in payload:
                fail("linker hints require a declared installation payload: " + destination)
            selected[name] = payload[source]
    if not selected:
        fail("explicit installed ELF inputs required for linker hints")
    output = ctx.actions.declare_file(ctx.label.name + "/linker.hints")
    if output.basename in selected:
        fail("linker hints output collides with an installed input")
    plan = ctx.actions.declare_file(ctx.label.name + ".inputs.json")
    files = [selected[name] for name in sorted(selected)]
    ctx.actions.write(plan, json.encode(dict(format = 1,
        tool = ctx.executable.tool.path,
        runtime = [file.path for file in ctx.files.tool_runtime],
        inputs = [dict(name = name, source = selected[name].path) for name in sorted(selected)])) + "\n")
    ctx.actions.run(executable = ctx.attr._python[DefaultInfo].files_to_run,
        arguments = ["-B", ctx.file._runner.path, plan.path, output.path],
        inputs = depset([plan, ctx.file._runner, ctx.file._python_home] + files + ctx.files._python_runtime),
        tools = [ctx.attr.tool[DefaultInfo].files_to_run] + ctx.files.tool_runtime,
        outputs = [output], env = {"LC_ALL": "C", "PYTHONHOME": ctx.file._python_home.dirname,
            "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": "", "LD_LIBRARY_PATH": ":".join(sorted(depset([file.dirname for file in ctx.files._python_runtime]).to_list()))},
        use_default_shell_env = False, mnemonic = "BSDLinkerHints")
    return [DefaultInfo(files = depset([output])),
        OutputGroupInfo(metadata = depset([plan])),
        BsdLinkerHintsInfo(output = output, directory = directory, inputs = selected,
            aliases = aliases, tool = ctx.executable.tool, runtime = ctx.files.tool_runtime, plan = plan),
        BsdInstallFileInfo(source = output, metadata = dict(type = "file", source = output.path,
            destination = directory.rstrip("/") + "/linker.hints", owner = "root", group = "wheel",
            mode = "0644", flags = "", tags = ["package=" + ctx.attr.package]))]

bsd_linker_hints = rule(implementation = _hints, attrs = {
    "installation": attr.label(providers = [BsdInstallManifestInfo], mandatory = True),
    "directory": attr.label(providers = [BuildSettingInfo], mandatory = True),
    "package": attr.string(default = "kernel"),
    "tool": attr.label(default = "//usr.sbin/kldxref:kldxref", executable = True, cfg = "exec"),
    "tool_runtime": attr.label_list(default = ["//lib/libelf:elf_shared", "//lib/libkldelf:kldelf_shared",
        "@bsd_sdk//toolchain:execution-runtime/lib/libc.so.7", "@bsd_sdk//toolchain:execution-runtime/lib/libsys.so.7"], allow_files = True, cfg = "exec"),
    "_runner": attr.label(default = Label(":linker_hints.py"), allow_single_file = True, cfg = "exec"),
    "_python": attr.label(default = "@bsd_sdk//toolchain:extra_python", executable = True, allow_single_file = True, cfg = "exec"),
    "_python_home": attr.label(default = "@bsd_sdk//toolchain:python-home/runtime.json", allow_single_file = True, cfg = "exec"),
    "_python_runtime": attr.label_list(default = ["@bsd_sdk//toolchain:python_stdlib"], allow_files = True, cfg = "exec"),
})
