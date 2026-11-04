# SPDX-License-Identifier: BSD-2-Clause
"""Loader font, help and version generation with declared native tools."""

def _library_directories(files):
    # Pure Python source/data directories are not native library search paths.
    return depset([file.dirname for file in files
        if file.basename.endswith(".so") or ".so." in file.basename]).to_list()

def _font(ctx):
    output = ctx.actions.declare_file(ctx.label.name + "/" + ctx.attr.output)
    args = ctx.actions.args()
    args.add_all(["-f", "compressed-source", "-o", output.path, ctx.file.src.path])
    ctx.actions.run(executable = ctx.attr.converter[DefaultInfo].files_to_run,
        arguments = [args], inputs = [ctx.file.src], tools = ctx.files.runtime,
        outputs = [output], use_default_shell_env = False,
        env = {"LC_ALL": "C", "LD_LIBRARY_PATH": ":".join(_library_directories(ctx.files.runtime))},
        mnemonic = "BSDLoaderFont")
    return [DefaultInfo(files = depset([output]))]

bsd_loader_font = rule(implementation = _font, attrs = {
    "src": attr.label(allow_single_file = True, mandatory = True),
    "output": attr.string(mandatory = True),
    "converter": attr.label(default = "//usr.bin/vtfontcvt:vtfontcvt", executable = True, cfg = "exec"),
    # Source-built C tools run against the native execution ABI, including in
    # composite cross SDKs. Target sysroot libraries are not execution libraries.
    "runtime": attr.label_list(default = [
        "@bsd_sdk//toolchain:execution-runtime/lib/libc.so.7",
        "@bsd_sdk//toolchain:execution-runtime/lib/libsys.so.7",
        "@bsd_sdk//toolchain:execution-runtime/libexec/ld-elf.so.1",
    ], allow_files = True, cfg = "exec"),
})

def _help(ctx):
    if not ctx.files.srcs:
        fail("loader help requires an ordered source list")
    for source in ctx.attr.srcs:
        if len(source[DefaultInfo].files.to_list()) != 1:
            fail("each ordered help input must identify exactly one file")
    output = ctx.actions.declare_file(ctx.label.name + "/" + ctx.attr.output)
    args = ctx.actions.args()
    args.add_all(["-B", "-S", ctx.file._runner.path, "--awk", ctx.executable.awk.path,
        "--script", ctx.file.script.path, "--output", output.path])
    args.add_all(ctx.files.srcs, before_each = "--source")
    args.add_all(ctx.files.awk_runtime, before_each = "--runtime")
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = [args], inputs = [ctx.file._runner, ctx.file.script, ctx.file.python_home] + ctx.files.srcs,
        tools = [ctx.attr.awk[DefaultInfo].files_to_run] + ctx.files.awk_runtime + ctx.files.python_runtime,
        outputs = [output], use_default_shell_env = False,
        env = {"LC_ALL": "C", "PYTHONHOME": ctx.file.python_home.dirname,
            "PYTHONNOUSERSITE": "1", "LD_LIBRARY_PATH": ":".join(_library_directories(ctx.files.python_runtime))},
        mnemonic = "BSDLoaderHelp")
    return [DefaultInfo(files = depset([output]))]

bsd_loader_help = rule(implementation = _help, attrs = {
    "srcs": attr.label_list(allow_files = True, mandatory = True),
    "output": attr.string(mandatory = True),
    "script": attr.label(default = "//stand/common:merge_help.awk", allow_single_file = True),
    "awk": attr.label(default = "@bsd_sdk//toolchain:awk", executable = True, allow_single_file = True, cfg = "exec"),
    "awk_runtime": attr.label_list(default = ["@bsd_sdk//toolchain:awk_runtime"], allow_files = True, cfg = "exec"),
    "python": attr.label(default = "@bsd_sdk//toolchain:extra_python", executable = True, allow_single_file = True, cfg = "exec"),
    "python_home": attr.label(default = "@bsd_sdk//toolchain:python-home/runtime.json", allow_single_file = True, cfg = "exec"),
    "python_runtime": attr.label_list(default = ["@bsd_sdk//toolchain:python_stdlib"], allow_files = True, cfg = "exec"),
    "_runner": attr.label(default = Label("//tools/build/bazel:loader_help.py"), allow_single_file = True),
})


def _version(ctx):
    metadata = ctx.attr.metadata[DefaultInfo].files.to_list() if ctx.attr.metadata else []
    if not ctx.attr.reproducible and len(metadata) != 1:
        fail("select exactly one explicit loader version metadata file outside reproducible mode")
    output = ctx.actions.declare_file(ctx.label.name + "/" + ctx.attr.output)
    args = ctx.actions.args()
    args.add_all(["-B", "-S", ctx.file._version_runner.path,
        "--script", ctx.file.script.path, "--version", ctx.file.version.path,
        "--output", output.path, "--description", ctx.attr.description, "--machine", ctx.attr.machine])
    tools = []
    for name in ["shell", "awk", "mktemp", "cat", "mv", "rm"]:
        target = getattr(ctx.attr, name)
        args.add_all(["--" + name, getattr(ctx.executable, name).path])
        tools.append(target[DefaultInfo].files_to_run)
    inputs = [ctx.file._version_runner, ctx.file.script, ctx.file.version, ctx.file.python_home]
    if ctx.attr.reproducible:
        args.add("--reproducible")
    else:
        args.add_all(["--metadata", metadata[0].path])
        inputs.append(metadata[0])
    args.add_all(ctx.files.tool_runtime, before_each = "--runtime")
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run, arguments = [args],
        inputs = inputs, tools = tools + ctx.files.tool_runtime + ctx.files.python_runtime,
        outputs = [output], use_default_shell_env = False,
        env = {"LC_ALL": "C", "PYTHONHOME": ctx.file.python_home.dirname,
            "PYTHONNOUSERSITE": "1", "LD_LIBRARY_PATH": ":".join(_library_directories(ctx.files.python_runtime))},
        mnemonic = "BSDLoaderVersion")
    return [DefaultInfo(files = depset([output]))]

bsd_loader_version = rule(implementation = _version, attrs = {
    "version": attr.label(allow_single_file = True, mandatory = True),
    "output": attr.string(mandatory = True),
    "description": attr.string(mandatory = True),
    "machine": attr.string(mandatory = True),
    "reproducible": attr.bool(mandatory = True),
    "metadata": attr.label(allow_files = True),
    "script": attr.label(default = "//stand/common:newvers.sh", allow_single_file = True),
    "shell": attr.label(default = "@bsd_sdk//toolchain:sh", executable = True, allow_single_file = True, cfg = "exec"),
    "awk": attr.label(default = "@bsd_sdk//toolchain:awk", executable = True, allow_single_file = True, cfg = "exec"),
    "mktemp": attr.label(default = "@bsd_sdk//toolchain:extra_mktemp", executable = True, allow_single_file = True, cfg = "exec"),
    "cat": attr.label(default = "@bsd_sdk//toolchain:cat", executable = True, allow_single_file = True, cfg = "exec"),
    "mv": attr.label(default = "@bsd_sdk//toolchain:mv", executable = True, allow_single_file = True, cfg = "exec"),
    "rm": attr.label(default = "@bsd_sdk//toolchain:rm", executable = True, allow_single_file = True, cfg = "exec"),
    "tool_runtime": attr.label_list(default = ["@bsd_sdk//toolchain:sh_runtime", "@bsd_sdk//toolchain:awk_runtime", "@bsd_sdk//toolchain:extra_mktemp_runtime", "@bsd_sdk//toolchain:cat_runtime", "@bsd_sdk//toolchain:mv_runtime", "@bsd_sdk//toolchain:rm_runtime"], allow_files = True, cfg = "exec"),
    "python": attr.label(default = "@bsd_sdk//toolchain:extra_python", executable = True, allow_single_file = True, cfg = "exec"),
    "python_home": attr.label(default = "@bsd_sdk//toolchain:python-home/runtime.json", allow_single_file = True, cfg = "exec"),
    "python_runtime": attr.label_list(default = ["@bsd_sdk//toolchain:python_stdlib"], allow_files = True, cfg = "exec"),
    "_version_runner": attr.label(default = Label("//tools/build/bazel:loader_version.py"), allow_single_file = True),
})
