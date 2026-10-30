# SPDX-License-Identifier: BSD-2-Clause
"""Generate kernel object interface source/header pairs from maintained .m files."""
def _impl(ctx):
    stem = ctx.file.src.basename[:-2]
    directory = ctx.label.name + ".generated/"
    source = ctx.actions.declare_file(directory + stem + ".c")
    header = ctx.actions.declare_file(directory + stem + ".h")
    # A stable input basename keeps generated provenance independent of execroot.
    interface = ctx.actions.declare_file(directory + ctx.file.src.basename)
    ctx.actions.symlink(output = interface, target_file = ctx.file.src)
    aliases = []
    for name, target in [("mv", ctx.attr.mv), ("rm", ctx.attr.rm)]:
        alias = ctx.actions.declare_file(ctx.label.name + ".tools/" + name)
        ctx.actions.symlink(output = alias, target_file = target[DefaultInfo].files_to_run.executable, is_executable = True)
        aliases.append(alias)
    args = ctx.actions.args()
    args.add_all(["-B", ctx.file.runner.path, ctx.executable.awk.path, ctx.file.generator.path, interface.path, aliases[0].dirname])
    args.add_all(ctx.files.libraries)
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = [args], inputs = [ctx.file.runner, ctx.file.generator, interface, ctx.file.src, ctx.file.python_home] + aliases + ctx.files.runtime + ctx.files.libraries,
        tools = [ctx.attr.awk[DefaultInfo].files_to_run, ctx.attr.mv[DefaultInfo].files_to_run, ctx.attr.rm[DefaultInfo].files_to_run],
        outputs = [source, header],
        env = {"LC_ALL": "C", "PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1"},
        use_default_shell_env = False, mnemonic = "BSDKobjInterface")
    return [DefaultInfo(files = depset([source, header])),
        OutputGroupInfo(source = depset([source]), header = depset([header]))]

bsd_kobj_interface = rule(implementation = _impl, attrs = {
    "src": attr.label(allow_single_file = [".m"], mandatory = True),
    "generator": attr.label(allow_single_file = True, default = "//sys/tools:makeobjops.awk"),
    "runner": attr.label(allow_single_file = True, default = "//tools/build/bazel:kobj_generate.py"),
    "awk": attr.label(executable = True, cfg = "exec", default = "//usr.bin/awk:awk"),
    "mv": attr.label(executable = True, cfg = "exec", default = "//bin/mv:mv"),
    "rm": attr.label(executable = True, cfg = "exec", default = "//bin/rm:rm"),
    "libraries": attr.label_list(allow_files = True, cfg = "exec"),
    "python": attr.label(executable = True, allow_single_file = True, cfg = "exec", mandatory = True),
    "python_home": attr.label(allow_single_file = True, cfg = "exec", mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
})


def kernel_interfaces(srcs, **kwargs):
    """Declare maintained interfaces; callers may override execution inputs."""
    defaults = {
        "python": "@bsd_sdk//toolchain:extra_python",
        "python_home": "@bsd_sdk//toolchain:python-home/runtime.json",
        "runtime": ["@bsd_sdk//toolchain:python_stdlib"],
        "libraries": ["//lib/msun:m_shared", "@bsd_sdk//toolchain:sysroot/lib/libc.so.7", "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7"],
        "visibility": ["//visibility:public"],
    }
    defaults.update(kwargs)
    for src in srcs:
        bsd_kobj_interface(name = src.split("/")[-1][:-2], src = src, **defaults)
