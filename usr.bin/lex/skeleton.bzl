# SPDX-License-Identifier: BSD-2-Clause
"""Execute the maintained flex skeleton pipeline with declared tools."""
def _skeleton(ctx):
    output = ctx.actions.declare_file("skel.c")
    # mkskel.sh calls sed by name. Its only PATH directory is the declared SDK
    # tool directory, and sed itself is a declared execution input.
    script = 'set -eu; version=$("$1" -f "$2" "$3"); "$4" -e -o pipefail "$5" "$6" "$7" "$version" > "$8"'
    ctx.actions.run(executable = ctx.executable.shell,
        arguments = ["-c", script, "flex-skeleton", ctx.executable.awk.path,
            ctx.file.version_script.path, ctx.file.config.path, ctx.executable.shell.path,
            ctx.file.script.path, ctx.file.skeleton.dirname, ctx.executable.m4.path, output.path],
        inputs = [ctx.file.version_script, ctx.file.config, ctx.file.script, ctx.file.skeleton] + ctx.files.includes,
        tools = [ctx.attr.awk[DefaultInfo].files_to_run, ctx.attr.sed[DefaultInfo].files_to_run,
            ctx.attr.m4[DefaultInfo].files_to_run] + ctx.files.runtime,
        outputs = [output], env = {"LC_ALL": "C", "PATH": ctx.executable.sed.dirname},
        use_default_shell_env = False, mnemonic = "FlexSkeleton")
    return [DefaultInfo(files = depset([output]))]
flex_skeleton = rule(implementation = _skeleton, attrs = {
    "config": attr.label(allow_single_file = True, mandatory = True),
    "version_script": attr.label(allow_single_file = True, mandatory = True),
    "script": attr.label(allow_single_file = True, mandatory = True),
    "skeleton": attr.label(allow_single_file = True, mandatory = True),
    "includes": attr.label_list(allow_files = True),
    "shell": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "awk": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "sed": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "m4": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
})
