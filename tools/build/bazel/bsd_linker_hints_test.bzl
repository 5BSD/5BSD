# SPDX-License-Identifier: BSD-2-Clause
"""Run the native execution tool against selected target ELF artifacts."""
load(":bsd_linker_hints.bzl", "BsdLinkerHintsInfo")

def _quote(text):
    return "'" + text.replace("'", "'\\''") + "'"

def _test(ctx):
    info = ctx.attr.hints[BsdLinkerHintsInfo]
    request = ctx.actions.declare_file(ctx.label.name + ".inputs.json")
    ctx.actions.write(request, json.encode(dict(format = 1,
        hints = info.output.short_path, tool = info.tool.short_path,
        runtime = [file.short_path for file in info.runtime], aliases = info.aliases,
        inputs = {name: file.short_path for name, file in info.inputs.items()})) + "\n")
    files = [request, info.output, info.tool, ctx.executable._python, ctx.file._python_home,
        ctx.file._script] + info.runtime + info.inputs.values() + ctx.files._python_runtime
    runfiles = ctx.runfiles(files = files).merge(ctx.attr._python[DefaultInfo].default_runfiles)
    for target in ctx.attr._python_runtime:
        runfiles = runfiles.merge(target[DefaultInfo].default_runfiles)
    runner = ctx.actions.declare_file(ctx.label.name + ".sh")
    root = '\"${TEST_SRCDIR}/${TEST_WORKSPACE}\"'
    runtime_dirs = sorted(depset([file.short_path.rsplit("/", 1)[0] for file in ctx.files._python_runtime]).to_list())
    library_path = ":".join([root + "/" + _quote(path) for path in runtime_dirs])
    ctx.actions.write(runner, "\n".join(["#!/bin/sh", "set -eu",
        "export PYTHONHOME=" + root + "/" + _quote(ctx.file._python_home.short_path.rsplit("/", 1)[0]),
        "export PYTHONNOUSERSITE=1", "export PYTHONDONTWRITEBYTECODE=1",
        "export PYTHONPATH=", "export LD_LIBRARY_PATH=" + library_path,
        "exec " + root + "/" + _quote(ctx.executable._python.short_path) + " -B " +
            root + "/" + _quote(ctx.file._script.short_path) + " " + root + "/" + _quote(request.short_path), ""]),
        is_executable = True)
    return [DefaultInfo(executable = runner, runfiles = runfiles)]

bsd_linker_hints_test = rule(implementation = _test, test = True, attrs = {
    "hints": attr.label(providers = [BsdLinkerHintsInfo], mandatory = True),
    "_script": attr.label(default = Label(":linker-hints-test.py"), allow_single_file = True),
    "_python": attr.label(default = "@bsd_sdk//toolchain:extra_python", executable = True, allow_single_file = True, cfg = config.exec("test")),
    "_python_home": attr.label(default = "@bsd_sdk//toolchain:python-home/runtime.json", allow_single_file = True, cfg = config.exec("test")),
    "_python_runtime": attr.label_list(default = ["@bsd_sdk//toolchain:python_stdlib"], allow_files = True, cfg = config.exec("test")),
}, exec_groups = {"test": exec_group(exec_compatible_with = ["@platforms//os:freebsd", "@bsd_sdk//toolchain:selected_sdk"])})
