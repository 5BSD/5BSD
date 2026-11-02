# SPDX-License-Identifier: BSD-2-Clause
"""Resolve explicitly declared object groups into a validated kernel link order."""
KernelLinkInputsInfo = provider(fields = {
    "objects": "Ordered object Files; consumers must preserve this list.",
    "validation": "Successful config inventory validation output.",
})


def _impl(ctx):
    inventory = [json.decode(row) for row in ctx.attr.inventory]
    order = ctx.attr.prefix + [row["object"] for row in inventory if row["object"] != None] + ctx.attr.suffix
    names = {name: True for name in order}
    if not order or len(order) != len(names):
        fail("kernel link order must contain unique object names")
    objects = {}
    for file in ctx.files.objects:
        if file.basename in objects:
            fail("ambiguous kernel link object: " + file.basename)
        objects[file.basename] = file
    missing = [name for name in order if name not in objects]
    surplus = [name for name in objects if name not in names]
    if missing or surplus:
        fail("kernel link object mismatch; missing: %s; surplus: %s" % (missing, surplus))
    declaration = ctx.actions.declare_file(ctx.label.name + ".declaration.json")
    validation = ctx.actions.declare_file(ctx.label.name + ".validated.json")
    expected = {"format": 1, "kernel_identity": ctx.attr.kernel_identity,
                "machine": ctx.attr.machine, "machine_arch": ctx.attr.machine_arch,
                "inputs": inventory}
    ctx.actions.write(declaration, json.encode(expected) + "\n")
    ctx.actions.run(
        executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = ["-B", "-S", ctx.file._runner.path, ctx.file.manifest.path,
                     declaration.path, validation.path],
        inputs = [ctx.file._runner, ctx.file.manifest, declaration, ctx.file.python_home] + ctx.files.runtime,
        outputs = [validation],
        env = {"LC_ALL": "C", "PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1"},
        use_default_shell_env = False, mnemonic = "BSDKernelInventoryValidate",
    )
    ordered = [objects[name] for name in order]
    return [DefaultInfo(files = depset(ordered)),
            KernelLinkInputsInfo(objects = ordered, validation = validation),
            OutputGroupInfo(validation = depset([validation]), declaration = depset([declaration]))]


bsd_kernel_inputs = rule(implementation = _impl, attrs = {
    "objects": attr.label_list(allow_files = True, mandatory = True),
    "inventory": attr.string_list(mandatory = True),
    "prefix": attr.string_list(), "suffix": attr.string_list(),
    "manifest": attr.label(allow_single_file = True, mandatory = True),
    "kernel_identity": attr.string(mandatory = True),
    "machine": attr.string(mandatory = True), "machine_arch": attr.string(mandatory = True),
    "python": attr.label(executable = True, allow_single_file = True, cfg = "exec", mandatory = True),
    "python_home": attr.label(allow_single_file = True, cfg = "exec", mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
    "_runner": attr.label(allow_single_file = True, default = "//tools/build/bazel:kernel_inventory_validate.py"),
})
