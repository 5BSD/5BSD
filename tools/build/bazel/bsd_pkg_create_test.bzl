# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the package driver with declared real pkg/tar tools and fixtures."""


def _quote(value):
    return "'" + value.replace("'", "'\\''") + "'"


def _test(ctx):
    root = '"${TEST_SRCDIR}/${TEST_WORKSPACE}"/'
    files = [ctx.executable.python, ctx.file.python_home, ctx.file.src, ctx.file.driver,
             ctx.executable.pkg, ctx.executable.tar, ctx.file.abi_file, ctx.file.osversion_header]
    targets = [ctx.attr.python, ctx.attr.python_home, ctx.attr.src, ctx.attr.driver,
               ctx.attr.pkg, ctx.attr.tar, ctx.attr.abi_file, ctx.attr.osversion_header] + ctx.attr.runtime
    files += ctx.files.runtime
    runfiles = ctx.runfiles(files = files).merge_all([t[DefaultInfo].default_runfiles for t in targets])
    library_dirs = {f.short_path.rsplit("/", 1)[0]: True for f in ctx.files.runtime}
    command = [
        "#!/bin/sh", "set -eu",
        "export PYTHONHOME=" + root + _quote(ctx.file.python_home.short_path.rsplit("/", 1)[0]),
        "export PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=",
        "export LD_LIBRARY_PATH=" + ":".join([root + _quote(p) for p in sorted(library_dirs)]),
        "exec " + root + _quote(ctx.executable.python.short_path) + " -B -S " + root + _quote(ctx.file.src.short_path) +
        " --driver " + root + _quote(ctx.file.driver.short_path) +
        " --pkg " + root + _quote(ctx.executable.pkg.short_path) +
        " --tar " + root + _quote(ctx.executable.tar.short_path) +
        " --abi-file " + root + _quote(ctx.file.abi_file.short_path) +
        " --osversion-header " + root + _quote(ctx.file.osversion_header.short_path) +
        ' --output "${TEST_UNDECLARED_OUTPUTS_DIR}/checks"',
    ]
    runner = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.write(runner, "\n".join(command) + "\n", is_executable = True)
    return [DefaultInfo(executable = runner, runfiles = runfiles)]

bsd_pkg_create_test = rule(implementation = _test, test = True, attrs = {
    "src": attr.label(default = Label(":pkg-create-directories-test.py"), allow_single_file = True),
    "driver": attr.label(default = Label(":pkg_create.py"), allow_single_file = True),
    "python": attr.label(default = "@bsd_sdk//toolchain:extra_python", executable = True, allow_single_file = True, cfg = "exec"),
    "python_home": attr.label(default = "@bsd_sdk//toolchain:python-home/runtime.json", allow_single_file = True, cfg = "exec"),
    "pkg": attr.label(default = "@bsd_sdk//toolchain:extra_pkg", executable = True, allow_single_file = True, cfg = "exec"),
    "tar": attr.label(default = "@bsd_sdk//toolchain:extra_tar", executable = True, allow_single_file = True, cfg = "exec"),
    "abi_file": attr.label(default = "@bsd_sdk//toolchain:sysroot/lib/libc.so.7", allow_single_file = True),
    "osversion_header": attr.label(default = Label("//sys/sys:param.h"), allow_single_file = True),
    "runtime": attr.label_list(default = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_pkg_runtime",
        "@bsd_sdk//toolchain:extra_tar_runtime"], allow_files = True, cfg = "exec"),
})
