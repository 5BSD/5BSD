# SPDX-License-Identifier: BSD-2-Clause
"""Generate a PMC event table with an execution-platform jevents tool."""

def _events(ctx):
    marker = ctx.file.mapfile
    if marker.dirname.split("/")[-1] != ctx.attr.architecture:
        fail("mapfile must belong to the selected architecture")
    inputs = ctx.files.event_files
    if marker not in inputs:
        fail("the architecture mapfile must be declared in event_files")
    root = marker.dirname.rsplit("/", 1)[0]
    output = ctx.actions.declare_file(ctx.attr.output)
    environment = {"LC_ALL": "C"}
    if ctx.files.runtime_libraries:
        environment["LD_LIBRARY_PATH"] = ":".join(depset([f.dirname for f in ctx.files.runtime_libraries]).to_list())
    ctx.actions.run(
        executable = ctx.attr.jevents[DefaultInfo].files_to_run,
        arguments = [ctx.attr.architecture, root, output.path],
        inputs = inputs,
        tools = ctx.files.runtime_libraries,
        outputs = [output],
        env = environment,
        use_default_shell_env = False,
        mnemonic = "BSDPmuEvents",
        progress_message = "Generating %s PMC events" % ctx.attr.architecture,
    )
    return [DefaultInfo(files = depset([output]))]

bsd_pmu_events = rule(
    implementation = _events,
    attrs = {
        "architecture": attr.string(mandatory = True),
        "mapfile": attr.label(allow_single_file = True, mandatory = True),
        "event_files": attr.label_list(allow_files = True, mandatory = True),
        "jevents": attr.label(executable = True, cfg = "exec", mandatory = True),
        "output": attr.string(mandatory = True),
        "runtime_libraries": attr.label_list(allow_files = True, cfg = "exec"),
    },
)
