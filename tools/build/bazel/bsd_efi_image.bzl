# SPDX-License-Identifier: BSD-2-Clause
"""EFI image conversion; source linking, policy and signing remain separate."""

def _efi(ctx):
    if not ctx.attr.sections:
        fail("EFI conversion requires the selected Make section list")
    epoch = ctx.attr.source_date_epoch
    if not epoch or any([c not in "0123456789" for c in epoch.elems()]) or int(epoch) > 4294967295:
        fail("SOURCE_DATE_EPOCH must fit an unsigned PE timestamp")
    out = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add_all(["-B", "-S", ctx.file._runner.path, "--src", ctx.file.src.path,
        "--output", out.path, "--nm", ctx.executable.nm.path,
        "--objcopy", ctx.executable.objcopy.path, "--format", ctx.attr.output_format,
        "--epoch", str(int(epoch))])
    for section in ctx.attr.sections:
        args.add_all(["--section", section])
    args.add("--nm-runtime")
    args.add_all(ctx.files.nm_runtime)
    args.add("--objcopy-runtime")
    args.add_all(ctx.files.objcopy_runtime)
    runtime_dirs = depset([file.dirname for file in ctx.files.python_runtime]).to_list()
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run, arguments = [args],
        inputs = [ctx.file.src, ctx.file._runner, ctx.file.python_home] + ctx.files.python_runtime,
        tools = [ctx.attr.nm[DefaultInfo].files_to_run, ctx.attr.objcopy[DefaultInfo].files_to_run] +
            ctx.files.nm_runtime + ctx.files.objcopy_runtime,
        outputs = [out], env = {"LC_ALL": "C", "PYTHONHOME": ctx.file.python_home.dirname,
            "PYTHONNOUSERSITE": "1", "LD_LIBRARY_PATH": ":".join(runtime_dirs)},
        use_default_shell_env = False, mnemonic = "BSDEfiImage")
    return [DefaultInfo(files = depset([out]))]

bsd_efi_image = rule(implementation = _efi, attrs = {
    "src": attr.label(allow_single_file = True, mandatory = True),
    "output": attr.string(mandatory = True),
    "output_format": attr.string(mandatory = True),
    # Decimal string retains the PE unsigned timestamp range beyond int32/2038.
    "source_date_epoch": attr.string(mandatory = True),
    "sections": attr.string_list(mandatory = True),
    "objcopy": attr.label(default = "//usr.bin/elfcopy:elfcopy", executable = True, cfg = "exec"),
    "objcopy_runtime": attr.label_list(allow_files = True, cfg = "exec", mandatory = True),
    "nm": attr.label(default = "@bsd_sdk//toolchain:bin/llvm-nm", executable = True, cfg = "exec", allow_single_file = True),
    "nm_runtime": attr.label_list(default = ["@bsd_sdk//toolchain:llvm-nm_runtime"], allow_files = True, cfg = "exec"),
    "python": attr.label(default = "@bsd_sdk//toolchain:extra_python", executable = True, cfg = "exec", allow_single_file = True),
    "python_home": attr.label(default = "@bsd_sdk//toolchain:python-home/runtime.json", allow_single_file = True, cfg = "exec"),
    "python_runtime": attr.label_list(default = ["@bsd_sdk//toolchain:python_stdlib"], allow_files = True, cfg = "exec"),
    "_runner": attr.label(default = "//tools/build/bazel:efi_image.py", allow_single_file = True),
})
