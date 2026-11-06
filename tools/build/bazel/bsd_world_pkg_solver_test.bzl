# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the real pkg solver using a complete declared world package set."""
load(":bsd_pkg_family.bzl", "BsdPackageFamilySetInfo")
load(":bsd_python_test.bzl", "BsdHostArtifactTestInfo")

def _quote(value):
    return "'" + value.replace("'", "'\\''") + "'"

def _test(ctx):
    packages = ctx.files.packages
    indexes = [f for f in packages if f.basename == "index.json"]
    if len(indexes) != 1:
        fail("one package index required")
    catalogue = ctx.attr.families[BsdPackageFamilySetInfo].catalogue
    request = ctx.actions.declare_file(ctx.label.name + ".json")
    ctx.actions.write(request, json.encode(dict(
        packages = [f.short_path for f in packages if f.basename.endswith(".pkg")],
        index = indexes[0].short_path, catalogue = catalogue.short_path,
        pkg = ctx.executable.pkg.short_path, abi_file = ctx.file.abi_file.short_path,
        osversion_header = ctx.file.osversion_header.short_path, helper = ctx.file.helper.short_path,
    )) + "\n")
    files = [request, catalogue, ctx.executable.python, ctx.file.python_home,
        ctx.file._driver, ctx.file.helper, ctx.executable.pkg, ctx.file.abi_file,
        ctx.file.osversion_header] + packages + ctx.files.runtime
    targets = [ctx.attr.python, ctx.attr.pkg] + ctx.attr.runtime
    root = '"${TEST_SRCDIR}/${TEST_WORKSPACE}"/'
    library_dirs = {f.short_path.rsplit("/", 1)[0]: True for f in ctx.files.runtime}
    runner = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.write(runner, "\n".join([
        "#!/bin/sh", "set -eu",
        "export PYTHONHOME=" + root + _quote(ctx.file.python_home.short_path.rsplit("/", 1)[0]),
        "export PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=",
        "export LD_LIBRARY_PATH=" + ":".join([root + _quote(p) for p in sorted(library_dirs)]),
        "exec " + root + _quote(ctx.executable.python.short_path) + " -B -S " + root + _quote(ctx.file._driver.short_path) +
        " --request " + root + _quote(request.short_path) + ' --output "${TEST_UNDECLARED_OUTPUTS_DIR}/checks" --work "${TEST_TMPDIR}/world-pkg-solver"',
    ]) + "\n", is_executable = True)
    return [DefaultInfo(executable = runner, runfiles = ctx.runfiles(files = files).merge_all([
        t[DefaultInfo].default_runfiles for t in targets])), BsdHostArtifactTestInfo()]

bsd_world_pkg_solver_test = rule(implementation = _test, test = True, attrs = {
    "packages": attr.label(mandatory = True),
    "families": attr.label(providers = [BsdPackageFamilySetInfo], mandatory = True),
    "abi_file": attr.label(allow_single_file = True, mandatory = True),
    "osversion_header": attr.label(default = Label("//sys/sys:param.h"), allow_single_file = True),
    "helper": attr.label(default = Label(":private-package-install-test.py"), allow_single_file = True),
    "pkg": attr.label(default = "@bsd_sdk//toolchain:extra_pkg", executable = True, allow_single_file = True, cfg = config.exec("test")),
    "python": attr.label(default = "@bsd_sdk//toolchain:extra_python", executable = True, allow_single_file = True, cfg = config.exec("test")),
    "python_home": attr.label(default = "@bsd_sdk//toolchain:python-home/runtime.json", allow_single_file = True, cfg = config.exec("test")),
    "runtime": attr.label_list(default = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_pkg_runtime", Label(":package_index.py")], allow_files = True, cfg = config.exec("test")),
    "_driver": attr.label(default = Label(":world-pkg-solver-test.py"), allow_single_file = True),
}, exec_groups = {"test": exec_group(exec_compatible_with = ["@platforms//os:freebsd", "@bsd_sdk//toolchain:selected_sdk"])})
