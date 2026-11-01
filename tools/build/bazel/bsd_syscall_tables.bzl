# SPDX-License-Identifier: BSD-2-Clause
"""Generate syscall tables with the maintained Lua generator modules."""
_KINDS = ["init_sysent", "libsys_h", "syscall_h", "syscall_mk", "syscall_bzl", "syscalls", "syscalls_map", "sysproto_h", "systrace_args"]

def _tables(ctx):
    if not ctx.attr.outputs:
        fail("at least one explicit syscall output is required")
    outputs = []
    groups = {}
    names = []
    arguments = ctx.actions.args()
    arguments.add(ctx.file._driver)
    arguments.add(ctx.file._module_anchor.dirname)
    arguments.add(ctx.file.master)
    arguments.add(ctx.file.config)
    for kind, name in sorted(ctx.attr.outputs.items()):
        if kind not in _KINDS:
            fail("unknown syscall generator: " + kind)
        if any([part in ["", ".", ".."] for part in name.split("/")]) or "\\" in name:
            fail("normalized relative output required: " + name)
        if name in names:
            fail("duplicate syscall output: " + name)
        names.append(name)
        output = ctx.actions.declare_file(name)
        outputs.append(output)
        groups[kind] = depset([output])
        arguments.add(kind)
        arguments.add(output)
    directories = []
    for library in ctx.files.runtime:
        if library.dirname not in directories:
            directories.append(library.dirname)
    ctx.actions.run(executable = ctx.attr.interpreter[DefaultInfo].files_to_run,
        arguments = [arguments],
        inputs = depset([ctx.file.master, ctx.file.config, ctx.file._driver, ctx.file._module_anchor],
            transitive = [ctx.attr._modules[DefaultInfo].files]),
        tools = ctx.files.runtime, outputs = outputs,
        env = {"LC_ALL": "C", "LUA_PATH": "", "LUA_CPATH": "", "LD_LIBRARY_PATH": ":".join(directories)},
        use_default_shell_env = False, mnemonic = "BSDSyscallTables")
    return [DefaultInfo(files = depset(outputs)), OutputGroupInfo(**groups)]

bsd_syscall_tables = rule(implementation = _tables, attrs = {
    "master": attr.label(allow_single_file = True, mandatory = True),
    "config": attr.label(allow_single_file = True, mandatory = True),
    "outputs": attr.string_dict(mandatory = True),
    "interpreter": attr.label(executable = True, cfg = "exec", default = Label("//libexec/flua:flua")),
    "runtime": attr.label_list(allow_files = True, cfg = "exec", default = [
        "//lib/libedit:edit_shared", "//lib/ncurses/tinfo:tinfo_shared", "//lib/msun:m_shared",
        "@bsd_sdk//toolchain:sysroot/lib/libc.so.7", "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7"]),
    "_driver": attr.label(allow_single_file = True, default = Label(":syscall_tables.lua")),
    "_modules": attr.label(default = Label("//sys/tools/syscalls:modules")),
    "_module_anchor": attr.label(allow_single_file = True, default = Label("//sys/tools/syscalls:config.lua")),
})
