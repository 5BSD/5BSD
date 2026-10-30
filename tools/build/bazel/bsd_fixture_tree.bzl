# SPDX-License-Identifier: BSD-2-Clause
"""Materialize declared regular-file fixtures as a Bazel directory artifact."""
def _tree(ctx):
    records = []
    destinations = {}
    inputs = []
    for target, destination in ctx.attr.sources.items():
        parts = destination.split("/")
        if any([part in ["", ".", ".."] for part in parts]) or "\\" in destination:
            fail("fixture destination must be normalized and relative: " + destination)
        if destination in destinations:
            fail("conflicting fixture destination: " + destination)
        files = target[DefaultInfo].files.to_list()
        if len(files) != 1 or files[0].is_directory:
            fail("each fixture must provide exactly one regular file")
        destinations[destination] = True
        inputs.append(files[0])
        records.append(dict(source = files[0].path, destination = destination))
    # Check parent prefixes once the complete namespace is known. This catches
    # both input orders without comparing every pair of fixture paths.
    for destination in destinations:
        parts = destination.split("/")
        for index in range(1, len(parts)):
            if "/".join(parts[:index]) in destinations:
                fail("conflicting fixture destination: " + destination)
    output = ctx.actions.declare_directory(ctx.label.name)
    manifest = ctx.actions.declare_file(ctx.label.name + ".inputs.json")
    ctx.actions.write(manifest, json.encode(records) + "\n")
    ctx.actions.run(executable = ctx.executable.python,
        arguments = ["-B", "-S", ctx.file._writer.path, manifest.path, output.path],
        inputs = inputs + [manifest, ctx.file._writer, ctx.file.python_home],
        tools = ctx.files.runtime, outputs = [output],
        env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1", "LC_ALL": "C"},
        use_default_shell_env = False, mnemonic = "BSDFixtureTree")
    return [DefaultInfo(files = depset([output])), OutputGroupInfo(metadata = depset([manifest]))]

bsd_fixture_tree = rule(implementation = _tree, attrs = {
    "sources": attr.label_keyed_string_dict(allow_files = True, mandatory = True),
    "python": attr.label(executable = True, allow_single_file = True, cfg = "exec", mandatory = True),
    "python_home": attr.label(allow_single_file = True, cfg = "exec", mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
    "_writer": attr.label(default = Label(":fixture_tree.py"), allow_single_file = True),
})
