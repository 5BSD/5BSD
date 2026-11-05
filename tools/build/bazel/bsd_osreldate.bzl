# SPDX-License-Identifier: BSD-2-Clause
"""Generate the public OS version header using declared source inputs/tools."""

def _generate(ctx):
    aliases, tools = [], [ctx.attr.redirect[DefaultInfo].files_to_run]
    for name in ["sh", "awk", "sed"]:
        tool = getattr(ctx.attr, name)[DefaultInfo].files_to_run
        alias = ctx.actions.declare_file(ctx.label.name + ".tools/" + name)
        ctx.actions.symlink(output = alias, target_file = tool.executable, is_executable = True)
        aliases.append(alias)
        tools.append(tool)
    ctx.actions.run(executable = ctx.attr.redirect[DefaultInfo].files_to_run,
        arguments = [ctx.outputs.output.path, ctx.executable.sh.path, ctx.file.script.path, "-s"],
        inputs = [ctx.file.script, ctx.file.newvers, ctx.file.param, ctx.file.copyright, ctx.file.template] + aliases,
        tools = tools + ctx.files.runtime, outputs = [ctx.outputs.output],
        env = {"LC_ALL": "C", "PATH": aliases[0].dirname,
            "NEWVERS_SH": ctx.file.newvers.path, "PARAMFILE": ctx.file.param.path,
            "NEWVERS_COPYRIGHT": ctx.file.copyright.path,
            "NEWVERS_COPYRIGHT_TEMPLATE": ctx.file.template.path}, use_default_shell_env = False,
        mnemonic = "BSDOsreldate")
    return [DefaultInfo(files = depset([ctx.outputs.output]))]

bsd_osreldate = rule(implementation = _generate, attrs = {
    "output": attr.output(mandatory = True),
    "script": attr.label(default = "//include:mk-osreldate.sh", allow_single_file = True),
    "newvers": attr.label(default = "//sys/conf:newvers.sh", allow_single_file = True),
    "param": attr.label(default = "//sys/sys:param.h", allow_single_file = True),
    "copyright": attr.label(default = "//:COPYRIGHT", allow_single_file = True),
    "template": attr.label(default = "//share/examples/etc:bsd-style-copyright", allow_single_file = True),
    "sh": attr.label(default = "@bsd_sdk//toolchain:sh", executable = True, allow_single_file = True, cfg = "exec"),
    "awk": attr.label(default = "@bsd_sdk//toolchain:awk", executable = True, allow_single_file = True, cfg = "exec"),
    "sed": attr.label(default = "@bsd_sdk//toolchain:sed", executable = True, allow_single_file = True, cfg = "exec"),
    "redirect": attr.label(default = "@bsd_sdk//toolchain:stdout_redirect", executable = True, allow_single_file = True, cfg = "exec"),
    "runtime": attr.label_list(default = ["@bsd_sdk//toolchain:sh_runtime", "@bsd_sdk//toolchain:awk_runtime", "@bsd_sdk//toolchain:sed_runtime"], allow_files = True, cfg = "exec"),
})
