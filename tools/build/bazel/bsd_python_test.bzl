# SPDX-License-Identifier: BSD-2-Clause
"""Run a Python test with the declared SDK interpreter and its runfiles."""

def _quote(value):
    return "'" + value.replace("'", "'\\''") + "'"

def _impl(ctx):
    python = ctx.executable.python
    python_home = ctx.file.python_home
    source = ctx.file.src
    files = [python, source, python_home] + ctx.files.data + ctx.files.runtime
    targets = [ctx.attr.python, ctx.attr.python_home] + ctx.attr.data + ctx.attr.runtime
    runfiles = ctx.runfiles(files = files).merge_all([
        target[DefaultInfo].default_runfiles
        for target in targets
    ])

    root = '"${TEST_SRCDIR}/${TEST_WORKSPACE}"'
    python_path = root + "/" + _quote(python.short_path)
    source_path = root + "/" + _quote(source.short_path)
    home_path = root + "/" + _quote(python_home.short_path.rsplit("/", 1)[0])
    runtime_dirs = {}
    for file in ctx.files.runtime:
        runtime_dirs[file.short_path.rsplit("/", 1)[0]] = True
    library_path = ":".join([root + "/" + _quote(path) for path in sorted(runtime_dirs.keys())])
    command = [
        "#!/bin/sh",
        "set -eu",
        "export PYTHONHOME=" + home_path,
        "export PYTHONNOUSERSITE=1",
        "export PYTHONDONTWRITEBYTECODE=1",
        "export LD_LIBRARY_PATH=" + library_path + "${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}",
        "exec " + python_path + " -B " + source_path + ' "$@"',
    ]
    runner = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.write(runner, "\n".join(command) + "\n", is_executable = True)
    return [DefaultInfo(executable = runner, runfiles = runfiles)]

bsd_python_test = rule(
    implementation = _impl,
    test = True,
    attrs = {
        "src": attr.label(allow_single_file = [".py"], mandatory = True),
        "data": attr.label_list(allow_files = True),
        "python": attr.label(default = "@bsd_sdk//toolchain:extra_python", executable = True, allow_single_file = True, cfg = "exec"),
        "python_home": attr.label(default = "@bsd_sdk//toolchain:python-home/runtime.json", allow_single_file = True, cfg = "exec"),
        "runtime": attr.label_list(default = ["@bsd_sdk//toolchain:python_stdlib"], allow_files = True, cfg = "exec"),
    },
)
