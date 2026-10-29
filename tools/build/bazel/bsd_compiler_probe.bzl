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
    if ctx.attr.coverage != bool(ctx.file.profile_runtime):
        fail("Coverage probes require an explicit profile runtime; other probes must omit it")
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
    inputs = [ctx.file.src]
    if ctx.attr.coverage:
        # Instrument compilation separately. Linking without the driver profiling
        # flag prevents Clang from selecting an implicit SDK runtime archive.
        obj = ctx.actions.declare_file(ctx.label.name + ".o")
        compile_args = ctx.actions.args()
        compile_args.add("--sysroot=" + stdio[0].path.removesuffix("/usr/include/stdio.h"))
        compile_args.add("-resource-dir", resource[0].path.removesuffix("/include/__stddef_size_t.h"))
        compile_args.add_all(["-O2", "-fprofile-instr-generate", "-fcoverage-mapping"])
        if ctx.attr.cxx:
            compile_args.add("--driver-mode=g++")
        if ctx.attr.lto != "none":
            compile_args.add("-flto=" + ctx.attr.lto)
        compile_args.add("-c", ctx.file.src)
        compile_args.add("-o", obj)
        ctx.actions.run(executable = ctx.attr.compiler[DefaultInfo].files_to_run,
            arguments = [compile_args], inputs = depset([ctx.file.src], transitive = [sdk]),
            outputs = [obj], env = {"LC_ALL": "C"}, use_default_shell_env = False,
            mnemonic = "BSDProfileCompile")
        args.add(obj)
        args.add("-Wl,-u,__llvm_profile_runtime")
        args.add(ctx.file.profile_runtime)
        inputs = [obj, ctx.file.profile_runtime]
    else:
        args.add(ctx.file.src)
    args.add("-o", out)
    ctx.actions.run(executable = ctx.attr.compiler[DefaultInfo].files_to_run,
        arguments = [args], inputs = depset(inputs, transitive = [sdk]),
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
    "coverage": attr.bool(),
    "profile_runtime": attr.label(allow_single_file = [".a"]),
    "lto": attr.string(default = "none", values = ["none", "full", "thin"]),
})
