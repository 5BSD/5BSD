# SPDX-License-Identifier: BSD-2-Clause
"""Capability database generation with explicit target byte order."""
def _capdb(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    if not output.path.endswith(".db"):
        fail("capability database output must end in .db")
    environment = {"LC_ALL": "C"}
    if ctx.files.runtime_libraries:
        environment["LD_LIBRARY_PATH"] = ":".join(sorted(depset([f.dirname for f in ctx.files.runtime_libraries]).to_list()))
    args = ctx.actions.args()
    args.add("-l" if ctx.attr.endian == "little" else "-b")
    args.add_all(["-f", output.path[:-3]])
    args.add_all(ctx.files.srcs)
    ctx.actions.run(executable = ctx.attr.compiler[DefaultInfo].files_to_run,
        arguments = [args], inputs = ctx.files.srcs,
        tools = ctx.files.runtime_libraries, outputs = [output],
        env = environment, use_default_shell_env = False, mnemonic = "BSDCapabilityDatabase")
    return [DefaultInfo(files = depset([output]))]

bsd_capability_database = rule(implementation = _capdb, attrs = {
    "srcs": attr.label_list(allow_files = True, mandatory = True, allow_empty = False),
    "output": attr.string(mandatory = True),
    "endian": attr.string(values = ["little", "big"], mandatory = True),
    "compiler": attr.label(executable = True, cfg = "exec", mandatory = True),
    "runtime_libraries": attr.label_list(allow_files = True, cfg = "exec"),
})
