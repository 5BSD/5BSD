# SPDX-License-Identifier: BSD-2-Clause
"""Native action ownership of the maintained upstream NTP version script."""
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")

def _impl(ctx):
    directory = ctx.label.name + ".generated/"
    source = ctx.actions.declare_file(directory + "version.c")
    counter = ctx.actions.declare_file(directory + ".version")
    metadata = ctx.actions.declare_file(directory + "metadata.json")
    args = ctx.actions.args()
    args.add_all(["-B", "-S", ctx.file._driver.path])
    args.add("--serial", ctx.attr.serial[BuildSettingInfo].value)
    args.add("--cset", ctx.attr.cset[BuildSettingInfo].value)
    args.add("--program", ctx.attr.program)
    args.add("--script", ctx.file._script)
    args.add("--shell", ctx.executable.shell)
    args.add("--output", source)
    args.add("--counter", counter)
    args.add("--metadata", metadata)
    tools = []
    for name in ["cat", "expr", "rm"]:
        target = getattr(ctx.attr, name)
        args.add("--tool", name + "=" + target[DefaultInfo].files_to_run.executable.path)
        tools.append(target[DefaultInfo].files_to_run)
    args.add_all(ctx.files.libraries, before_each = "--library")
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = [args], inputs = [ctx.file._script, ctx.file._driver, ctx.file.python_home] + ctx.files.libraries,
        tools = tools + [ctx.attr.shell[DefaultInfo].files_to_run] + ctx.files.runtime,
        outputs = [source, counter, metadata],
        env = {"PYTHONHOME":ctx.file.python_home.dirname, "PYTHONNOUSERSITE":"1", "LC_ALL":"C"},
        use_default_shell_env = False, mnemonic = "NtpVersion")
    return [DefaultInfo(files = depset([source])),
            OutputGroupInfo(metadata = depset([counter, metadata]))]

ntp_version = rule(implementation = _impl, attrs = {
    "program": attr.string(mandatory = True),
    "serial": attr.label(default = "//usr.sbin/ntp:version_serial", providers = [BuildSettingInfo]),
    "cset": attr.label(default = "//usr.sbin/ntp:version_cset", providers = [BuildSettingInfo]),
    "shell": attr.label(default = "@bsd_sdk//toolchain:sh", executable = True, allow_single_file = True, cfg = "exec"),
    "cat": attr.label(default = "//bin/cat:cat", executable = True, cfg = "exec"),
    "expr": attr.label(default = "//bin/expr:expr", executable = True, cfg = "exec"),
    "rm": attr.label(default = "//bin/rm:rm", executable = True, cfg = "exec"),
    "python": attr.label(default = "@bsd_sdk//toolchain:extra_python", executable = True, allow_single_file = True, cfg = "exec"),
    "python_home": attr.label(default = "@bsd_sdk//toolchain:python-home/runtime.json", allow_single_file = True, cfg = "exec"),
    "libraries": attr.label_list(default = ["@bsd_sdk//toolchain:sh_runtime"], allow_files = True, cfg = "exec"),
    "runtime": attr.label_list(default = ["@bsd_sdk//toolchain:python_stdlib"], allow_files = True, cfg = "exec"),
    "_script": attr.label(default = Label("//usr.sbin/ntp:scripts/mkver"), allow_single_file = True),
    "_driver": attr.label(default = Label("//usr.sbin/ntp:ntp_version.py"), allow_single_file = True),
})
