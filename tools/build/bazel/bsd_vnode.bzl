# SPDX-License-Identifier: BSD-2-Clause
"""Generate the four maintained vnode interface artifacts in one declared action."""
def _quote(value):
    return "'" + value.replace("'", "'\\''") + "'"

def _impl(ctx):
    outputs = [ctx.actions.declare_file(ctx.label.name + ".generated/" + name)
               for name in ["vnode_if.c", "vnode_if.h", "vnode_if_newproto.h", "vnode_if_typedef.h"]]
    library_dirs = []
    for file in ctx.files.libraries:
        if file.dirname not in library_dirs:
            library_dirs.append(file.dirname)
    command = 'set -eu\nroot="$(pwd -P)"\ncd ' + _quote(outputs[0].dirname) + '\n'
    if library_dirs:
        command += 'LD_LIBRARY_PATH=' + ':'.join(['"$root/"' + _quote(d) for d in library_dirs]) + '\nexport LD_LIBRARY_PATH\n'
    command += 'exec "$root/"' + _quote(ctx.executable.awk.path) + ' -f "$root/"' + _quote(ctx.file.generator.path) + ' "$root/"' + _quote(ctx.file.src.path) + ' -chpq\n'
    ctx.actions.run(executable = ctx.attr.shell[DefaultInfo].files_to_run,
        arguments = ["-c", command],
        inputs = [ctx.file.src, ctx.file.generator] + ctx.files.libraries,
        tools = [ctx.attr.awk[DefaultInfo].files_to_run] + ctx.files.runtime,
        outputs = outputs, env = {"LC_ALL": "C"},
        use_default_shell_env = False, mnemonic = "BSDVnodeInterface")
    return [DefaultInfo(files = depset(outputs)),
        OutputGroupInfo(source = depset(outputs[:1]), headers = depset(outputs[1:]))]

bsd_vnode_interface = rule(implementation = _impl, attrs = {
    "src": attr.label(allow_single_file = [".src"], mandatory = True),
    "generator": attr.label(allow_single_file = True, default = "//sys/tools:vnode_if.awk"),
    "awk": attr.label(executable = True, cfg = "exec", default = "//usr.bin/awk:awk"),
    "shell": attr.label(executable = True, allow_single_file = True, cfg = "exec", mandatory = True),
    "libraries": attr.label_list(allow_files = True, cfg = "exec"),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
})
