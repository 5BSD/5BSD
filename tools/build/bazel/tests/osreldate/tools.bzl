# SPDX-License-Identifier: BSD-2-Clause
"""Explicit execution tools exposed under stable test runfile aliases."""
def _tools(ctx):
    targets = [ctx.attr.sh, ctx.attr.awk, ctx.attr.sed] + ctx.attr.runtime
    files = [ctx.executable.sh, ctx.executable.awk, ctx.executable.sed] + ctx.files.runtime
    return [DefaultInfo(files = depset(files), runfiles = ctx.runfiles(files = files,
        symlinks = {"osreldate-tools/" + name: getattr(ctx.executable, name) for name in ["sh", "awk", "sed"]}).merge_all(
            [target[DefaultInfo].default_runfiles for target in targets]))]
execution_tools = rule(implementation = _tools, attrs = {
    "sh": attr.label(default = "@bsd_sdk//toolchain:sh", executable = True, allow_single_file = True, cfg = "exec"),
    "awk": attr.label(default = "@bsd_sdk//toolchain:awk", executable = True, allow_single_file = True, cfg = "exec"),
    "sed": attr.label(default = "@bsd_sdk//toolchain:sed", executable = True, allow_single_file = True, cfg = "exec"),
    "runtime": attr.label_list(default = ["@bsd_sdk//toolchain:sh_runtime", "@bsd_sdk//toolchain:awk_runtime", "@bsd_sdk//toolchain:sed_runtime"], allow_files = True, cfg = "exec"),
})
