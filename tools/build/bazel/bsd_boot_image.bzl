# SPDX-License-Identifier: BSD-2-Clause
"""Declared BIOS image transformations and the original BTX linker invocation."""

def _environment(files):
    result = {"LC_ALL": "C"}
    if files:
        result["LD_LIBRARY_PATH"] = ":".join(depset([file.dirname for file in files]).to_list())
    return result

def _symbols(ctx):
    out = ctx.actions.declare_file(ctx.attr.output)
    ctx.actions.run(executable = ctx.attr.redirect[DefaultInfo].files_to_run,
        arguments = [out.path, ctx.executable.nm.path, "-t", "d", ctx.file.src.path],
        inputs = [ctx.file.src], tools = [ctx.attr.nm[DefaultInfo].files_to_run] + ctx.files.runtime,
        outputs = [out], env = _environment(ctx.files.runtime), use_default_shell_env = False,
        mnemonic = "BSDBootSymbols")
    return [DefaultInfo(files = depset([out]))]

bsd_boot_symbols = rule(implementation = _symbols, attrs = {
    "src": attr.label(allow_single_file = True, mandatory = True),
    "output": attr.string(mandatory = True),
    "nm": attr.label(default = "@bsd_sdk//toolchain:bin/llvm-nm", executable = True, cfg = "exec", allow_single_file = True),
    "runtime": attr.label_list(default = ["@bsd_sdk//toolchain:llvm-nm_runtime"], allow_files = True, cfg = "exec"),
    "redirect": attr.label(default = "@bsd_sdk//toolchain:stdout_redirect", executable = True, cfg = "exec"),
})

def _flat(ctx):
    out = ctx.actions.declare_file(ctx.attr.output)
    ctx.actions.run(executable = ctx.attr.objcopy[DefaultInfo].files_to_run,
        arguments = ["-S", "-O", "binary", ctx.file.src.path, out.path],
        inputs = [ctx.file.src], tools = ctx.files.runtime, outputs = [out],
        env = _environment(ctx.files.runtime), use_default_shell_env = False, mnemonic = "BSDBootFlatImage")
    return [DefaultInfo(files = depset([out]))]

bsd_boot_flat_image = rule(implementation = _flat, attrs = {
    "src": attr.label(allow_single_file = True, mandatory = True),
    "output": attr.string(mandatory = True),
    "objcopy": attr.label(default = "@bsd_sdk//toolchain:bin/llvm-objcopy", executable = True, cfg = "exec", allow_single_file = True),
    "runtime": attr.label_list(default = ["@bsd_sdk//toolchain:objcopy_inputs"], allow_files = True, cfg = "exec"),
})

def _btx(ctx):
    out = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add_all(["-v", "-E", ctx.attr.entry, "-f", "bin", "-b", ctx.file.kernel.path,
        "-l", ctx.file.loader.path, "-o", out.path])
    if ctx.attr.page_control:
        args.add_all(["-P", str(ctx.attr.page_control)])
    args.add(ctx.file.src)
    ctx.actions.run(executable = ctx.attr.tool[DefaultInfo].files_to_run, arguments = [args],
        inputs = [ctx.file.src, ctx.file.kernel, ctx.file.loader], tools = ctx.files.runtime,
        outputs = [out], env = _environment(ctx.files.runtime), use_default_shell_env = False,
        mnemonic = "BSDBtxImage")
    return [DefaultInfo(files = depset([out]))]

bsd_btx_image = rule(implementation = _btx, attrs = {
    "src": attr.label(allow_single_file = True, mandatory = True),
    "kernel": attr.label(allow_single_file = True, mandatory = True),
    "loader": attr.label(allow_single_file = True, mandatory = True),
    "entry": attr.string(mandatory = True),
    "page_control": attr.int(default = 0),
    "output": attr.string(mandatory = True),
    "tool": attr.label(default = "//usr.sbin/btxld:btxld", executable = True, cfg = "exec"),
    "runtime": attr.label_list(default = ["@bsd_sdk//toolchain:sysroot/lib/libc.so.7", "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7"], allow_files = True, cfg = "exec"),
})

def _bytes(ctx):
    if ctx.attr.operation == "zero" and (ctx.files.srcs or ctx.attr.size < 1):
        fail("zero requires no inputs and a positive size")
    if ctx.attr.operation == "pad" and (len(ctx.files.srcs) != 1 or ctx.attr.size < 1):
        fail("pad requires one input and a positive size")
    if ctx.attr.operation == "concat" and (len(ctx.files.srcs) < 2 or ctx.attr.size != 0):
        fail("concat requires at least two ordered inputs and no size")
    out = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add_all(["-B", "-S", ctx.file._runner.path, "--operation", ctx.attr.operation,
        "--size", str(ctx.attr.size), "--output", out.path])
    args.add_all(ctx.files.srcs)
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run, arguments = [args],
        inputs = ctx.files.srcs + [ctx.file._runner, ctx.file.python_home] + ctx.files.runtime,
        outputs = [out], env = {"LC_ALL": "C", "PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1"},
        use_default_shell_env = False, mnemonic = "BSDBootImageBytes")
    return [DefaultInfo(files = depset([out]))]

bsd_boot_image_bytes = rule(implementation = _bytes, attrs = {
    "srcs": attr.label_list(allow_files = True),
    "operation": attr.string(mandatory = True, values = ["zero", "pad", "concat"]),
    "size": attr.int(),
    "output": attr.string(mandatory = True),
    "python": attr.label(default = "@bsd_sdk//toolchain:extra_python", executable = True, cfg = "exec", allow_single_file = True),
    "python_home": attr.label(default = "@bsd_sdk//toolchain:python-home/runtime.json", allow_single_file = True, cfg = "exec"),
    "runtime": attr.label_list(default = ["@bsd_sdk//toolchain:python_stdlib"], allow_files = True, cfg = "exec"),
    "_runner": attr.label(default = "//tools/build/bazel:boot_image.py", allow_single_file = True),
})

def _link(ctx):
    if not ctx.files.objects or len(depset(ctx.files.objects).to_list()) != len(ctx.files.objects):
        fail("boot link requires nonempty distinct ordered objects")
    out = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add_all(ctx.attr.linkopts)
    args.add_all(["-T", ctx.file.script.path, "-o", out.path])
    args.add_all(ctx.files.objects)
    ctx.actions.run(executable = ctx.attr.linker[DefaultInfo].files_to_run,
        arguments = [args], inputs = ctx.files.objects + [ctx.file.script], tools = ctx.files.runtime,
        outputs = [out], env = _environment(ctx.files.runtime), use_default_shell_env = False,
        mnemonic = "BSDBootLink")
    return [DefaultInfo(files = depset([out]))]

bsd_boot_link = rule(implementation = _link, attrs = {
    "objects": attr.label_list(allow_files = True, mandatory = True),
    "script": attr.label(allow_single_file = True, mandatory = True),
    "linkopts": attr.string_list(mandatory = True),
    "output": attr.string(mandatory = True),
    "linker": attr.label(default = "@bsd_sdk//toolchain:bin/ld.lld", executable = True, cfg = "exec", allow_single_file = True),
    "runtime": attr.label_list(default = ["@bsd_sdk//toolchain:ld.lld_runtime"], allow_files = True, cfg = "exec"),
})
