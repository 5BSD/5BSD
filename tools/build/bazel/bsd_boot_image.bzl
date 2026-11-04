# SPDX-License-Identifier: BSD-2-Clause
"""Declared BIOS image transformations and the original BTX linker invocation."""

load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")

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
    if bool(ctx.attr.entry) == bool(ctx.attr.entry_setting):
        fail("select exactly one explicit BTX entry value or setting")
    entry = ctx.attr.entry
    if ctx.attr.entry_setting:
        value = ctx.attr.entry_setting[BuildSettingInfo].value
        if type(value) != "int" or value < 0 or value > 4294967295:
            fail("BTX entry must fit an unsigned 32-bit address")
        entry = str(value)
    args.add_all(["-v", "-E" if ctx.attr.entry_kind == "client" else "-e", entry, "-f", ctx.attr.output_format, "-b", ctx.file.kernel.path,
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
    "entry": attr.string(),
    "entry_setting": attr.label(providers = [BuildSettingInfo]),
    "entry_kind": attr.string(default = "client", values = ["client", "output"]),
    "output_format": attr.string(default = "bin", values = ["bin", "aout", "elf"]),
    "page_control": attr.int(default = 0),
    "output": attr.string(mandatory = True),
    "tool": attr.label(default = "//usr.sbin/btxld:btxld", executable = True, cfg = "exec"),
    "runtime": attr.label_list(default = ["@bsd_sdk//toolchain:sysroot/lib/libc.so.7", "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7"], allow_files = True, cfg = "exec"),
})

def _bytes(ctx):
    size = ctx.attr.size
    if ctx.attr.size_setting:
        if size != 0:
            fail("select either an explicit boot image size or a setting")
        size = ctx.attr.size_setting[BuildSettingInfo].value
        if type(size) != "int" or size < 1:
            fail("boot image size limit must be a positive integer")
    if ctx.attr.operation == "zero" and (ctx.files.srcs or size < 1):
        fail("zero requires no inputs and a positive size")
    if ctx.attr.operation in ["pad", "check"] and (len(ctx.files.srcs) != 1 or size < 1):
        fail("pad/check requires one input and a positive size")
    if ctx.attr.operation == "concat" and (len(ctx.files.srcs) < 2 or size != 0):
        fail("concat requires at least two ordered inputs and no size")
    out = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add_all(["-B", "-S", ctx.file._runner.path, "--operation", ctx.attr.operation,
        "--size", str(size), "--output", out.path])
    args.add_all(ctx.files.srcs)
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run, arguments = [args],
        inputs = ctx.files.srcs + [ctx.file._runner, ctx.file.python_home] + ctx.files.runtime,
        outputs = [out], env = {"LC_ALL": "C", "PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1"},
        use_default_shell_env = False, mnemonic = "BSDBootImageBytes")
    return [DefaultInfo(files = depset([out]))]

bsd_boot_image_bytes = rule(implementation = _bytes, attrs = {
    "srcs": attr.label_list(allow_files = True),
    "operation": attr.string(mandatory = True, values = ["zero", "pad", "concat", "check"]),
    "size": attr.int(),
    "size_setting": attr.label(providers = [BuildSettingInfo]),
    "output": attr.string(mandatory = True),
    "python": attr.label(default = "@bsd_sdk//toolchain:extra_python", executable = True, cfg = "exec", allow_single_file = True),
    "python_home": attr.label(default = "@bsd_sdk//toolchain:python-home/runtime.json", allow_single_file = True, cfg = "exec"),
    "runtime": attr.label_list(default = ["@bsd_sdk//toolchain:python_stdlib"], allow_files = True, cfg = "exec"),
    "_runner": attr.label(default = "//tools/build/bazel:boot_image.py", allow_single_file = True),
})

def _link(ctx):
    if not ctx.files.objects or len(depset(ctx.files.objects).to_list()) != len(ctx.files.objects):
        fail("boot link requires nonempty distinct ordered objects")
    archives = []
    for target in ctx.attr.archives:
        files = target[DefaultInfo].files.to_list()
        if len(files) != 1 or files[0].extension != "a":
            fail("each boot archive must select one native archive")
        archives.append(files[0])
    inputs = ctx.files.objects + archives
    if len(depset(inputs).to_list()) != len(inputs):
        fail("duplicate boot link inputs")
    out = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add_all(ctx.attr.linkopts)
    if ctx.attr.origin_setting:
        origin = ctx.attr.origin_setting[BuildSettingInfo].value
        if type(origin) != "int" or origin < 0 or origin > 4294967295:
            fail("boot link origin must fit an unsigned 32-bit address")
        args.add_all(["--defsym", "ORG=" + str(origin)])
    args.add_all(["-T", ctx.file.script.path, "-o", out.path])
    args.add_all(inputs)
    ctx.actions.run(executable = ctx.attr.linker[DefaultInfo].files_to_run,
        arguments = [args], inputs = inputs + [ctx.file.script], tools = ctx.files.runtime,
        outputs = [out], env = _environment(ctx.files.runtime), use_default_shell_env = False,
        mnemonic = "BSDBootLink")
    return [DefaultInfo(files = depset([out]))]

bsd_boot_link = rule(implementation = _link, attrs = {
    "objects": attr.label_list(allow_files = True, mandatory = True),
    "archives": attr.label_list(allow_files = [".a"]),
    "script": attr.label(allow_single_file = True, mandatory = True),
    "origin_setting": attr.label(providers = [BuildSettingInfo]),
    "linkopts": attr.string_list(mandatory = True),
    "output": attr.string(mandatory = True),
    "linker": attr.label(default = "@bsd_sdk//toolchain:bin/ld.lld", executable = True, cfg = "exec", allow_single_file = True),
    "runtime": attr.label_list(default = ["@bsd_sdk//toolchain:ld.lld_runtime"], allow_files = True, cfg = "exec"),
})

def _strip_client(ctx):
    maximum = ctx.attr.maximum[BuildSettingInfo].value
    if type(maximum) != "int" or maximum <= 0:
        fail("boot client size limit must be a positive integer")
    output = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add_all(["-B", "-S", ctx.file._runner.path, "--source", ctx.file.src.path,
        "--output", output.path, "--strip", ctx.executable.strip.path, "--max-size", str(maximum), "--runtime"])
    args.add_all(ctx.files.strip_runtime)
    env = _environment([file for file in ctx.files.python_runtime if file.basename.endswith(".so") or ".so." in file.basename])
    env.update({"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1"})
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = [args], inputs = [ctx.file.src, ctx.file._runner, ctx.file.python_home] + ctx.files.python_runtime,
        tools = [ctx.attr.strip[DefaultInfo].files_to_run] + ctx.files.strip_runtime,
        outputs = [output], env = env, use_default_shell_env = False, mnemonic = "BSDBootStripClient")
    return [DefaultInfo(files = depset([output]))]

bsd_boot_strip_client = rule(implementation = _strip_client, attrs = {
    "src": attr.label(allow_single_file = True, mandatory = True),
    "output": attr.string(mandatory = True),
    "maximum": attr.label(providers = [BuildSettingInfo], mandatory = True),
    "strip": attr.label(default = "@bsd_sdk//toolchain:bin/llvm-strip", executable = True, cfg = "exec", allow_single_file = True),
    "strip_runtime": attr.label_list(default = ["@bsd_sdk//toolchain:strip_inputs"], allow_files = True, cfg = "exec"),
    "python": attr.label(default = "@bsd_sdk//toolchain:extra_python", executable = True, cfg = "exec", allow_single_file = True),
    "python_home": attr.label(default = "@bsd_sdk//toolchain:python-home/runtime.json", allow_single_file = True, cfg = "exec"),
    "python_runtime": attr.label_list(default = ["@bsd_sdk//toolchain:python_stdlib"], allow_files = True, cfg = "exec"),
    "_runner": attr.label(default = "//tools/build/bazel:boot_strip.py", allow_single_file = True),
})
