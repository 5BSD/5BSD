# SPDX-License-Identifier: BSD-2-Clause
"""Run maintained file-producing device-ID AWK generators with declared tools."""

def _impl(ctx):
    directory = ctx.label.name + ".generated/"
    filename = ctx.attr.header
    if not filename.endswith(".h") or any([c in filename for c in ["/", "\\", "\n", "\r", "\t"]]):
        fail("device-ID output must be a header basename")
    header = ctx.actions.declare_file(directory + filename)
    aliases = []
    for source in [ctx.file.src, ctx.file.generator] + ctx.files.libraries:
        alias = ctx.actions.declare_file(directory + source.basename)
        ctx.actions.symlink(output = alias, target_file = source)
        aliases.append(alias)
    args = ctx.actions.args()
    args.add_all([header.dirname, ctx.executable.awk.path, "-f", ctx.file.generator.basename, ctx.file.src.basename] + ctx.attr.arguments)
    ctx.actions.run(
        executable = ctx.attr.runner[DefaultInfo].files_to_run,
        arguments = [args],
        inputs = aliases + [ctx.file.src, ctx.file.generator] + ctx.files.libraries,
        tools = [ctx.attr.awk[DefaultInfo].files_to_run],
        outputs = [header],
        # cwd_exec is static. The awk loader resolves only declared library
        # aliases in its output directory, after the runner changes directory.
        env = {"LC_ALL": "C", "LD_LIBRARY_PATH": ".", "PATH": ""},
        use_default_shell_env = False,
        mnemonic = ctx.attr.mnemonic,
    )
    return [DefaultInfo(files = depset([header]))]

bsd_device_ids_header = rule(implementation = _impl, attrs = {
    "src": attr.label(allow_single_file = True, mandatory = True),
    "generator": attr.label(allow_single_file = True, mandatory = True),
    "header": attr.string(mandatory = True),
    "arguments": attr.string_list(),
    "mnemonic": attr.string(default = "BSDDeviceIds"),
    "awk": attr.label(executable = True, cfg = "exec", default = "//usr.bin/awk:awk"),
    "runner": attr.label(executable = True, cfg = "exec", default = "//tools/build/bazel:cwd_exec"),
    "libraries": attr.label_list(allow_files = True, cfg = "exec", default = [
        "//lib/msun:m_shared",
        "@bsd_sdk//toolchain:sysroot/lib/libc.so.7",
        "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7",
    ]),
})
