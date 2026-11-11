# SPDX-License-Identifier: BSD-2-Clause
"""A declared source namespace for the maintained DQ resolution audit."""

def _impl(ctx):
    root = ctx.path(ctx.attr.source_marker).dirname.get_child("sys")
    result = ctx.execute(
        [ctx.path(ctx.attr.python), "-B", "-S", ctx.path(ctx.attr.scanner), root],
        environment = {"PYTHONHOME": str(ctx.path(ctx.attr.python_home).dirname),
                       "PYTHONNOUSERSITE": "1", "LC_ALL": "C"}, quiet = True)
    if result.return_code:
        fail("kernel audit inventory discovery failed: " + result.stderr)
    inventory = json.decode(result.stdout)
    # Watch names/types, not contents. All C/header contents are normal action
    # inputs, so new lookup sites invalidate the check without repository scans.
    root.readdir(watch = "yes")
    labels = ["sources/.dq-audit-root"]
    ctx.file(labels[0], "")
    for relative in inventory["directories"]:
        root.get_child(relative).readdir(watch = "yes")
        # Retain empty directories through declared zero-byte markers.
        marker = "sources/" + relative + "/.dq-audit-directory"
        ctx.file(marker, "")
        labels.append(marker)
    for relative in inventory["files"]:
        path = "sources/" + relative
        ctx.symlink(root.get_child(relative), path)
        labels.append(path)
    ctx.file("BUILD.bazel", 'exports_files(' + repr(labels + ["source.list", "inventory.json"]) + ', visibility = ["//visibility:public"])\n' +
        'filegroup(name = "sources", srcs = ' + repr(labels) + ', visibility = ["//visibility:public"])\n')
    ctx.file("source.list", "\n".join(inventory["files"]) + "\n")
    ctx.file("inventory.json", json.encode(inventory) + "\n")

kernel_audit_repository = repository_rule(implementation = _impl, attrs = {
    "source_marker": attr.label(allow_single_file = True, mandatory = True),
    "python": attr.label(allow_single_file = True, mandatory = True),
    "python_home": attr.label(allow_single_file = True, mandatory = True),
    "scanner": attr.label(default = Label(":kernel_audit_sources.py"), allow_single_file = True),
}, local = True)
