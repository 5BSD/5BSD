# SPDX-License-Identifier: BSD-2-Clause
"""Compile a runnable probe with the candidate compiler and explicitly selected SDK.

This deliberately tests a staged SDK, not independent bootstrap or installation.
SDK roots are resolved from declared header artifacts, never the running host.
"""

def _impl(ctx):
    sdk = depset(transitive = [target[DefaultInfo].files for target in ctx.attr.sdk])
    stdio = [f for f in sdk.to_list() if f.path.endswith("/sysroot/usr/include/stdio.h")]
    resource = [f for f in sdk.to_list() if "/sysroot/usr/lib/clang/" in f.path and f.path.endswith("/include/__stddef_size_t.h")]
    if len(stdio) != 1 or len(resource) != 1:
        fail("Compiler probe requires one SDK sysroot and one Clang resource header set")
    out = ctx.actions.declare_file(ctx.label.name + ".bin")
    args = ctx.actions.args()
    args.add("--sysroot=" + stdio[0].path.removesuffix("/usr/include/stdio.h"))
    args.add("-resource-dir", resource[0].path.removesuffix("/include/__stddef_size_t.h"))
    args.add("--ld-path=" + ctx.file.linker.path)
    args.add("-fuse-ld=lld")
    args.add_all(["-O2", "-static"])
    if ctx.attr.lto != "none":
        args.add("-flto=" + ctx.attr.lto)
    if ctx.attr.cxx:
        args.add("--driver-mode=g++")
    args.add(ctx.file.src)
    args.add("-o", out)
    ctx.actions.run(executable = ctx.attr.compiler[DefaultInfo].files_to_run,
        arguments = [args], inputs = depset([ctx.file.src], transitive = [sdk]),
        tools = [ctx.attr.linker[DefaultInfo].files_to_run], outputs = [out],
        env = {"LC_ALL": "C"}, use_default_shell_env = False,
        mnemonic = "BSDCompilerProbe")
    return [DefaultInfo(executable = out, files = depset([out]))]

bsd_compiler_probe = rule(implementation = _impl, executable = True, attrs = {
    "compiler": attr.label(executable = True, cfg = "exec", mandatory = True),
    "linker": attr.label(allow_single_file = True, executable = True, cfg = "exec", mandatory = True),
    "sdk": attr.label_list(mandatory = True),
    "src": attr.label(allow_single_file = True, mandatory = True),
    "cxx": attr.bool(),
    "lto": attr.string(default = "none", values = ["none", "full", "thin"]),
})
