# SPDX-License-Identifier: BSD-2-Clause
"""Declared vendor sed/AWK command-table generation; no ambient PATH tools."""
def _impl(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add_all(["-B", "-S", ctx.file._driver.path])
    for name, value in [("sed", ctx.executable.sed), ("awk", ctx.executable.awk),
                        ("sed-script", ctx.file.sed_script), ("awk-script", ctx.file.awk_script),
                        ("source", ctx.file.src), ("output", output)]:
        args.add("--" + name, value)
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = [args], inputs = [ctx.file._driver, ctx.file.sed_script, ctx.file.awk_script, ctx.file.src, ctx.file.python_home],
        tools = [ctx.attr.sed[DefaultInfo].files_to_run, ctx.attr.awk[DefaultInfo].files_to_run] + ctx.files.runtime,
        outputs = [output], env = {"LC_ALL": "C", "PATH": "/nonexistent", "PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1"},
        use_default_shell_env = False, mnemonic = "MITCommandTable")
    return [DefaultInfo(files = depset([output]))]
mit_command_table = rule(implementation = _impl, attrs = {
    "src": attr.label(allow_single_file = [".ct"], mandatory = True),
    "output": attr.string(mandatory = True),
    "sed_script": attr.label(allow_single_file = True, default = "//crypto/krb5/src/util/ss:ct_c_sed.in"),
    "awk_script": attr.label(allow_single_file = True, default = "//crypto/krb5/src/util/ss:ct_c_awk.in"),
    "sed": attr.label(executable = True, cfg = "exec", allow_single_file = True, default = "@bsd_sdk//toolchain:sed"),
    "awk": attr.label(executable = True, cfg = "exec", allow_single_file = True, default = "@bsd_sdk//toolchain:awk"),
    "python": attr.label(executable = True, cfg = "exec", allow_single_file = True, default = "@bsd_sdk//toolchain:extra_python"),
    "python_home": attr.label(cfg = "exec", allow_single_file = True, default = "@bsd_sdk//toolchain:python-home/runtime.json"),
    "runtime": attr.label_list(cfg = "exec", allow_files = True, default = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:sed_runtime", "@bsd_sdk//toolchain:awk_runtime"]),
    "_driver": attr.label(allow_single_file = True, default = Label(":command_table.py"), cfg = "exec"),
})
