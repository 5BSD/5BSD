# SPDX-License-Identifier: BSD-2-Clause
"""Declared account database generation from an explicit master.passwd input."""
def _accounts(ctx):
    outputs = {name: ctx.actions.declare_file(ctx.label.name + "/" + name)
               for name in ["master.passwd", "passwd", "pwd.db", "spwd.db"]}
    ctx.actions.run(
        executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = ["-B", "-S", ctx.file._driver.path, ctx.executable.pwd_mkdb.path,
                     ctx.file.src.path, ctx.file.shells.path, outputs["master.passwd"].dirname],
        inputs = [ctx.file.src, ctx.file.shells, ctx.file._driver, ctx.file.python_home],
        tools = [ctx.attr.pwd_mkdb[DefaultInfo].files_to_run] + ctx.files.runtime,
        outputs = outputs.values(),
        env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1", "LC_ALL": "C"},
        use_default_shell_env = False,
        mnemonic = "BSDAccountDatabases",
    )
    return [DefaultInfo(files = depset(outputs.values())),
            OutputGroupInfo(master_passwd = depset([outputs["master.passwd"]]),
                            passwd = depset([outputs["passwd"]]),
                            pwd_db = depset([outputs["pwd.db"]]),
                            spwd_db = depset([outputs["spwd.db"]]))]

bsd_account_databases = rule(implementation = _accounts, attrs = {
    "src": attr.label(allow_single_file = True, mandatory = True),
    "shells": attr.label(allow_single_file = True, mandatory = True),
    "pwd_mkdb": attr.label(executable = True, cfg = "exec", mandatory = True),
    "python": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "python_home": attr.label(allow_single_file = True, cfg = "exec", mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
    "_driver": attr.label(default = Label("//tools/build/bazel:generate_accounts.py"), allow_single_file = True),
})
