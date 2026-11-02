# SPDX-License-Identifier: BSD-2-Clause
"""Separate declared VDSO link and validation/offset-generation actions."""

def _link(ctx):
    if not ctx.files.objects or len(depset(ctx.files.objects).to_list()) != len(ctx.files.objects):
        fail("VDSO link requires nonempty unique ordered objects")
    image = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add_all(ctx.attr.linkopts)
    args.add_all(["-T", ctx.file.script.path, "-o", image.path])
    args.add_all(ctx.files.objects)
    ctx.actions.run(executable = ctx.attr.linker[DefaultInfo].files_to_run,
        arguments = [args], inputs = [ctx.file.script] + ctx.files.objects,
        tools = ctx.files.linker_runtime, outputs = [image],
        env = {"LC_ALL": "C", "LD_LIBRARY_PATH": ":".join(depset([f.dirname for f in ctx.files.linker_runtime]).to_list())},
        use_default_shell_env = False, mnemonic = "BSDVdsoLink")
    return [DefaultInfo(files = depset([image]))]

bsd_vdso_link = rule(implementation = _link, attrs = {
    "objects": attr.label_list(allow_files = True, mandatory = True),
    "script": attr.label(allow_single_file = True, mandatory = True),
    "linkopts": attr.string_list(mandatory = True),
    "output": attr.string(mandatory = True),
    "linker": attr.label(default = "@bsd_sdk//toolchain:bin/ld.lld", executable = True, cfg = "exec", allow_single_file = True),
    "linker_runtime": attr.label_list(default = ["@bsd_sdk//toolchain:ld.lld_runtime"], allow_files = True, cfg = "exec"),
})

def _validate(ctx):
    image = ctx.actions.declare_file(ctx.attr.directory + "/" + ctx.file.src.basename)
    header = ctx.actions.declare_file(ctx.attr.directory + "/" + ctx.attr.header)
    args = ctx.actions.args()
    args.add_all(["-B", "-S", ctx.file._runner.path, "--src", ctx.file.src.path,
        "--image", image.path, "--header", header.path,
        "--maximum-size", str(ctx.attr.maximum_size), "--machine", str(ctx.attr.machine),
        "--osabi", str(ctx.attr.osabi), "--symbol", ctx.attr.symbol,
        "--macro", ctx.attr.macro, "--soname", ctx.attr.soname])
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = [args], inputs = [ctx.file.src, ctx.file._runner, ctx.file.python_home] + ctx.files.runtime,
        outputs = [image, header],
        env = {"LC_ALL": "C", "PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1"},
        use_default_shell_env = False, mnemonic = "BSDVdsoValidate")
    return [DefaultInfo(files = depset([image, header])),
        OutputGroupInfo(image = depset([image]), header = depset([header]))]

bsd_vdso_validate = rule(implementation = _validate, attrs = {
    "src": attr.label(allow_single_file = True, mandatory = True),
    "directory": attr.string(mandatory = True),
    "header": attr.string(mandatory = True),
    "maximum_size": attr.int(mandatory = True),
    "machine": attr.int(mandatory = True),
    "osabi": attr.int(mandatory = True),
    "symbol": attr.string(mandatory = True),
    "macro": attr.string(mandatory = True),
    "soname": attr.string(mandatory = True),
    "python": attr.label(default = "@bsd_sdk//toolchain:extra_python", executable = True, allow_single_file = True, cfg = "exec"),
    "python_home": attr.label(default = "@bsd_sdk//toolchain:python-home/runtime.json", allow_single_file = True, cfg = "exec"),
    "runtime": attr.label_list(default = ["@bsd_sdk//toolchain:python_stdlib"], allow_files = True, cfg = "exec"),
    "_runner": attr.label(default = "//tools/build/bazel:vdso_validate.py", allow_single_file = True),
})
