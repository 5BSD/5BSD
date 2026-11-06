# SPDX-License-Identifier: BSD-2-Clause
"""Reconcile complete world inventory with source-selected family metadata."""
load(":bsd_pkg_family.bzl", "BsdPackageFamilySetInfo")

def _reconcile(ctx):
    catalogue = ctx.attr.families[BsdPackageFamilySetInfo].catalogue
    output = ctx.actions.declare_file(ctx.label.name + ".json")
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = ["-B", "-S", ctx.file._driver.path, ctx.file.inventory.path, catalogue.path, output.path],
        inputs = [ctx.file._driver, ctx.file.inventory, catalogue, ctx.file.python_home] + ctx.attr.families[BsdPackageFamilySetInfo].manifests.values(),
        tools = ctx.files.runtime, outputs = [output],
        env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1", "LC_ALL": "C"},
        use_default_shell_env = False, mnemonic = "BSDWorldPackageReconciliation")
    return [DefaultInfo(files = depset([output])), OutputGroupInfo(metadata = depset([output]))]

bsd_world_package_reconciliation = rule(implementation = _reconcile, attrs = {
    "inventory": attr.label(allow_single_file = True, mandatory = True),
    "families": attr.label(providers = [BsdPackageFamilySetInfo], mandatory = True),
    "python": attr.label(default = "@bsd_sdk//toolchain:extra_python", executable = True, allow_single_file = True, cfg = "exec"),
    "python_home": attr.label(default = "@bsd_sdk//toolchain:python-home/runtime.json", allow_single_file = True, cfg = "exec"),
    "runtime": attr.label_list(default = ["@bsd_sdk//toolchain:python_stdlib"], allow_files = True, cfg = "exec"),
    "_driver": attr.label(default = Label(":world_package_reconcile.py"), allow_single_file = True),
})
