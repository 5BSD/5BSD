# SPDX-License-Identifier: BSD-2-Clause
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")

def _version(ctx):
    output = ctx.actions.declare_file("freebsd-version")
    args = ctx.actions.args()
    args.add_all(["-B", "-S", ctx.file._driver.path])
    for name in ["newvers", "param", "template"]:
        args.add("--" + name, getattr(ctx.file, name))
    args.add("--shell", ctx.executable.shell)
    args.add("--awk", ctx.executable.awk)
    args.add("--branch", ctx.attr.branch[BuildSettingInfo].value)
    args.add("--output", output)
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = [args], outputs = [output],
        inputs = [ctx.file.newvers, ctx.file.param, ctx.file.template, ctx.file._driver, ctx.file.python_home],
        tools = [ctx.attr.shell[DefaultInfo].files_to_run, ctx.attr.awk[DefaultInfo].files_to_run] + ctx.files.runtime,
        env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1", "LC_ALL": "C"},
        use_default_shell_env = False, mnemonic = "BSDUserlandVersion")
    return [DefaultInfo(files = depset([output]))]

bsd_freebsd_version = rule(implementation = _version, attrs = {
    "newvers": attr.label(allow_single_file = True, mandatory = True),
    "param": attr.label(allow_single_file = True, mandatory = True),
    "template": attr.label(allow_single_file = True, mandatory = True),
    "branch": attr.label(providers = [BuildSettingInfo], mandatory = True),
    "shell": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "awk": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "python": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "python_home": attr.label(cfg = "exec", allow_single_file = True, mandatory = True),
    "runtime": attr.label_list(cfg = "exec", allow_files = True),
    "_driver": attr.label(default = Label("//tools/build/bazel:freebsd_version.py"), allow_single_file = True),
})
