# SPDX-License-Identifier: BSD-2-Clause
"""Native actions corresponding to bsd.nls.mk message catalogue generation."""

def _catalogue(ctx):
    if not ctx.files.sources:
        fail("catalogue requires message sources")
    if ctx.attr.concatenate:
        message = ctx.actions.declare_file(ctx.outputs.output.basename + ".msg", sibling = ctx.outputs.output)
        ctx.actions.run(
            executable = ctx.executable.redirect,
            arguments = [message.path, ctx.executable.cat.path] + [f.path for f in ctx.files.sources],
            inputs = ctx.files.sources,
            tools = [ctx.executable.cat] + ctx.files.runtime,
            outputs = [message],
            env = {"LC_ALL": "C"},
            use_default_shell_env = False,
            mnemonic = "BSDCatalogueSources",
        )
    else:
        if len(ctx.files.sources) != 1:
            fail("uncombined catalogue requires one message source")
        message = ctx.files.sources[0]
    ctx.actions.run(
        executable = ctx.executable.gencat,
        arguments = [ctx.outputs.output.path, message.path],
        inputs = [message],
        tools = ctx.files.runtime,
        outputs = [ctx.outputs.output],
        env = {"LC_ALL": "C"},
        use_default_shell_env = False,
        mnemonic = "BSDCatalogue",
    )
    return [DefaultInfo(files = depset([ctx.outputs.output]))]

bsd_catalogue = rule(
    implementation = _catalogue,
    attrs = {
        "sources": attr.label_list(allow_files = True, mandatory = True),
        "concatenate": attr.bool(),
        "output": attr.output(mandatory = True),
        "gencat": attr.label(executable = True, cfg = "exec", allow_files = True, mandatory = True),
        "cat": attr.label(executable = True, cfg = "exec", allow_files = True, mandatory = True),
        "redirect": attr.label(executable = True, cfg = "exec", mandatory = True),
        "runtime": attr.label_list(allow_files = True, cfg = "exec"),
    },
)
