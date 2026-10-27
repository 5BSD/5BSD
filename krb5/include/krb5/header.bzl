# SPDX-License-Identifier: BSD-2-Clause
"""Assemble the public interface in the maintained Make error-table order."""
def _header(ctx):
    output = ctx.actions.declare_file("krb5.h")
    prefix = ctx.actions.declare_file(ctx.label.name + ".prefix")
    suffix = ctx.actions.declare_file(ctx.label.name + ".suffix")
    ctx.actions.write(prefix, "/* This file is generated, please don't edit it directly.  */\n#ifndef KRB5_KRB5_H_INCLUDED\n#define KRB5_KRB5_H_INCLUDED\n")
    ctx.actions.write(suffix, "#endif /* KRB5_KRB5_H_INCLUDED */\n")
    inputs = [prefix, ctx.file.interface] + ctx.files.error_headers + [suffix]
    ctx.actions.run(executable = ctx.executable.redirect,
        arguments = [output.path, ctx.executable.cat.path] + [f.path for f in inputs],
        inputs = inputs, tools = [ctx.attr.cat[DefaultInfo].files_to_run] + ctx.files.runtime,
        outputs = [output], env = {"LC_ALL": "C"}, use_default_shell_env = False, mnemonic = "MITPublicHeader")
    return [DefaultInfo(files = depset([output]))]
krb5_header = rule(implementation = _header, attrs = {
    "interface": attr.label(allow_single_file = True, mandatory = True),
    "error_headers": attr.label_list(allow_files = True, mandatory = True),
    "cat": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "redirect": attr.label(executable = True, cfg = "exec", mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
})
