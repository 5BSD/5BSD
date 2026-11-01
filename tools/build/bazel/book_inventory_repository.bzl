# SPDX-License-Identifier: BSD-2-Clause
"""Declared source view for the maintained book inventory generators."""

def _impl(ctx):
    root = ctx.path(ctx.attr.source_marker).dirname.realpath
    result = ctx.execute(
        [ctx.path(ctx.attr.python), "-B", "-S", ctx.path(ctx.attr.scanner), root],
        environment = {
            "PYTHONHOME": str(ctx.path(ctx.attr.python_home).dirname),
            "PYTHONNOUSERSITE": "1",
            "LC_ALL": "C",
        },
        quiet = True,
    )
    if result.return_code:
        fail("book source inventory discovery failed: " + result.stderr)
    discovery = json.decode(result.stdout)

    # DirectoryListingValue records names and entry types in the supported
    # Bazel 9 port. This detects file/directory/symlink replacement without
    # watching every file's content during repository evaluation. Selected
    # file contents are ordinary inputs to the inventory actions.
    for relative in discovery["directories"]:
        root.get_child(relative).readdir(watch = "yes")

    groups = discovery["groups"]
    selected = {}
    for group in groups.values():
        for relative in group:
            if relative in selected:
                fail("book inventory groups overlap: " + relative)
            selected[relative] = True
            ctx.symlink(root.get_child(relative), "sources/" + relative)

    content = "# Generated from the maintained source inventory scanner.\n"
    for group in sorted(groups):
        labels = [":sources/" + relative for relative in groups[group]]
        content += "filegroup(name = " + repr(group + "_inventory_sources") + \
            ", srcs = " + repr(labels) + ", visibility = [\"//visibility:public\"])\n"
    content += 'exports_files(["inventory.json"])\n'
    ctx.file("inventory.json", json.encode(groups) + "\n")
    ctx.file("BUILD.bazel", content)

book_inventory_repository = repository_rule(
    implementation = _impl,
    attrs = {
        "source_marker": attr.label(allow_single_file = True, mandatory = True),
        "python": attr.label(allow_single_file = True, mandatory = True),
        "python_home": attr.label(allow_single_file = True, mandatory = True),
        "scanner": attr.label(default = Label(":book_inventory_sources.py"), allow_single_file = True),
    },
    local = True,
)
