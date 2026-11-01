# SPDX-License-Identifier: BSD-2-Clause
"""Maintained MT RPC generation and kernel include filtering as declared actions."""
load(":bsd_rpcgen.bzl", "bsd_rpcgen")

def _filter(ctx):
    output = ctx.outputs.output
    ctx.actions.run(
        executable = ctx.attr.redirect[DefaultInfo].files_to_run,
        arguments = [output.path, ctx.executable.grep.path, "-v", "--", ctx.attr.pattern, ctx.file.src.path],
        inputs = [ctx.file.src] + ctx.files.runtime,
        tools = [ctx.attr.grep[DefaultInfo].files_to_run],
        outputs = [output],
        env = {"LC_ALL": "C", "LD_LIBRARY_PATH": ":".join([f.dirname for f in ctx.files.runtime])},
        use_default_shell_env = False,
        mnemonic = "BsdKernelRpcFilter",
    )
    return [DefaultInfo(files = depset([output]))]

_kernel_rpc_filter = rule(implementation = _filter, attrs = {
    "src": attr.label(allow_single_file = True, mandatory = True),
    "output": attr.output(mandatory = True),
    "pattern": attr.string(mandatory = True),
    "grep": attr.label(executable = True, cfg = "exec", default = "//usr.bin/grep:grep"),
    "redirect": attr.label(executable = True, allow_single_file = True, cfg = "exec", default = "@bsd_sdk//toolchain:stdout_redirect"),
    "runtime": attr.label_list(allow_files = True, cfg = "exec", default = [
        "//lib/libregex:regex_shared", "@bsd_sdk//toolchain:sysroot/lib/libc.so.7", "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7",
    ]),
})

def kernel_rpc_protocol(name, source):
    """Match kmod's rpcgen -hM/-lM filters and unmodified rpcgen -c output."""
    for suffix, mode, pattern in [(".h", "-h", "pthread.h"), ("_clnt.c", "-l", "string.h"), ("_xdr.c", "-c", "")]:
        output = name + suffix
        raw = output + ".unfiltered" if pattern else output
        bsd_rpcgen(name = name + "_generate" + suffix.replace(".", "_"), source = source,
            output = raw, mode = mode, flags = ["-M"] if pattern else [],
            output_to_stdout = bool(pattern),
            cpp_flags = ["-E", "-x", "c", "-nostdinc"],
            rpcgen = "//usr.bin/rpcgen:rpcgen", cpp = "@bsd_sdk//toolchain:bin/cpp",
            compiler_inputs = "@bsd_sdk//toolchain:compile_inputs", runtime = ["@bsd_sdk//toolchain:cpp_runtime"])
        if pattern:
            _kernel_rpc_filter(name = name + "_filter" + suffix.replace(".", "_"),
                src = ":" + raw, output = output, pattern = pattern)
