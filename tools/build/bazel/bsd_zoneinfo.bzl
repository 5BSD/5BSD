# SPDX-License-Identifier: BSD-2-Clause
"""Native timezone compilation and maintained vendor source generation."""

def _libraries(files):
    return depset([f.dirname for f in files if f.basename.endswith(".so") or ".so." in f.basename]).to_list()

def _compile(ctx):
    output = ctx.actions.declare_directory(ctx.label.name)
    args = ctx.actions.args()
    # Zic owns creation inside its declared tree. Make's -D only skips mkdir
    # after its shell recipe precreates the same directories; format is unchanged.
    args.add_all(["-d", output.path, "-b", "fat", "-m", "0444"])
    if ctx.file.leapseconds:
        args.add_all(["-L", ctx.file.leapseconds.path])
    args.add_all(ctx.files.srcs)
    ctx.actions.run(executable = ctx.attr.zic[DefaultInfo].files_to_run,
        arguments = [args], inputs = ctx.files.srcs + ctx.files.leapseconds,
        tools = ctx.files.runtime, outputs = [output], use_default_shell_env = False,
        env = {"LC_ALL": "C", "LD_LIBRARY_PATH": ":".join(_libraries(ctx.files.runtime))},
        mnemonic = "BSDZoneinfoCompile")
    return [DefaultInfo(files = depset([output]))]

bsd_zoneinfo_compile = rule(implementation = _compile, attrs = {
    "srcs": attr.label_list(allow_files = True, mandatory = True, allow_empty = False),
    "leapseconds": attr.label(allow_single_file = True),
    "zic": attr.label(default = "//usr.sbin/zic:zic", executable = True, cfg = "exec"),
    "runtime": attr.label_list(default = ["@bsd_sdk//toolchain:execution-runtime/lib/libc.so.7",
        "@bsd_sdk//toolchain:execution-runtime/lib/libsys.so.7", "@bsd_sdk//toolchain:execution-runtime/libexec/ld-elf.so.1"], allow_files = True, cfg = "exec"),
})

def _source(ctx):
    output = ctx.actions.declare_file(ctx.label.name + "/tzdata.zi")
    args = ctx.actions.args()
    args.add_all(["-B", "-S", ctx.file._writer.path, "--awk", ctx.executable.awk.path,
        "--guard", ctx.file.guard.path, "--shrink", ctx.file.shrink.path,
        "--version", ctx.file.version.path, "--output", output.path])
    args.add_all(ctx.files.srcs)
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = [args], inputs = [ctx.file._writer, ctx.file.guard, ctx.file.shrink,
            ctx.file.version, ctx.file.python_home] + ctx.files.srcs,
        tools = [ctx.attr.awk[DefaultInfo].files_to_run] + ctx.files.runtime,
        outputs = [output], use_default_shell_env = False,
        env = {"LC_ALL": "C", "PYTHONHOME": ctx.file.python_home.dirname,
            "PYTHONNOUSERSITE": "1", "LD_LIBRARY_PATH": ":".join(_libraries(ctx.files.runtime))},
        mnemonic = "BSDZoneinfoSource")
    return [DefaultInfo(files = depset([output]))]

bsd_zoneinfo_source = rule(implementation = _source, attrs = {
    "srcs": attr.label_list(allow_files = True, mandatory = True, allow_empty = False),
    "guard": attr.label(allow_single_file = True, mandatory = True),
    "shrink": attr.label(allow_single_file = True, mandatory = True),
    "version": attr.label(allow_single_file = True, mandatory = True),
    "awk": attr.label(default = "@bsd_sdk//toolchain:awk", allow_single_file = True, executable = True, cfg = "exec"),
    "python": attr.label(default = "@bsd_sdk//toolchain:extra_python", allow_single_file = True, executable = True, cfg = "exec"),
    "python_home": attr.label(default = "@bsd_sdk//toolchain:python-home/runtime.json", allow_single_file = True, cfg = "exec"),
    "runtime": attr.label_list(default = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:awk_runtime"], allow_files = True, cfg = "exec"),
    "_writer": attr.label(default = Label(":zoneinfo_source.py"), allow_single_file = True),
})
