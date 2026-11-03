# SPDX-License-Identifier: BSD-2-Clause
"""Freestanding target ABI using compiler artifacts from the selected host SDK."""
load("@rules_cc//cc:cc_toolchain_config_lib.bzl", "action_config", "tool", "feature", "flag_group", "flag_set")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc/toolchains:cc_toolchain_config_info.bzl", "CcToolchainConfigInfo")

_COMPILE = ["c-compile", "c++-compile", "assemble", "preprocess-assemble", "c++-header-parsing",
    "linkstamp-compile", "lto-backend", "c++-module-compile", "c++-module-codegen"]
_LINK = ["c++-link-executable", "c++-link-dynamic-library", "c++-link-nodeps-dynamic-library"]

def _impl(ctx):
    # Bind actions to declared File artifacts. Package-relative tool_path strings
    # cannot address a different repository; do not synthesize escaping paths or
    # embed the selected SDK's absolute installation path.
    compile_actions = _COMPILE
    actions = [action_config(action_name = name, enabled = True,
        tools = [tool(tool = ctx.file.cc_driver)],
        implies = ["legacy_compile_flags", "user_compile_flags", "sysroot",
            "unfiltered_compile_flags", "compiler_input_flags", "compiler_output_flags"])
        for name in compile_actions]
    actions += [action_config(action_name = name, enabled = True,
        tools = [tool(tool = ctx.file.cc_driver)],
        implies = ["output_execpath_flags", "library_search_directories", "libraries_to_link",
            "user_link_flags", "legacy_link_flags", "linker_param_file", "sysroot"] +
            (["shared_flag"] if name != "c++-link-executable" else []))
        for name in _LINK]
    actions.append(action_config(action_name = "c++-link-static-library", enabled = True,
        tools = [tool(tool = ctx.file.archiver)], implies = ["archiver_flags", "linker_param_file"]))
    actions.append(action_config(action_name = "strip", enabled = True,
        tools = [tool(tool = ctx.file.strip)], flag_sets = [flag_set(flag_groups = [
            flag_group(flags = ["-S", "-p", "-o", "%{output_file}"]),
            flag_group(iterate_over = "stripopts", flags = ["%{stripopts}"]),
            flag_group(flags = ["%{input_file}"]),
        ])]))
    features = [
        feature(name = "opt", flag_sets = [flag_set(actions = _COMPILE,
            flag_groups = [flag_group(flags = ["-O2"])])]),
        feature(name = "dbg", flag_sets = [flag_set(actions = _COMPILE,
            flag_groups = [flag_group(flags = ["-O0"])])]),
        feature(name = "fastbuild", flag_sets = [flag_set(actions = _COMPILE,
            flag_groups = [flag_group(flags = ["-O0"])])]),
        feature(name = "bsd_kernel_target", enabled = True, flag_sets = [
            flag_set(actions = _COMPILE + _LINK,
                flag_groups = [flag_group(flags = ["--target=" + ctx.attr.target])])]),
        feature(name = "bsd_kernel_freestanding", enabled = True, flag_sets = [
            flag_set(actions = _COMPILE,
                flag_groups = [flag_group(flags = ["-nostdinc", "-ffreestanding", "-fdebug-compilation-dir=."])])]),
        # A kernel link must supply its declared scripts/objects. Do not search
        # the host libc or add userland startup objects on a foreign target.
        feature(name = "bsd_kernel_link", enabled = True, flag_sets = [flag_set(
            actions = _LINK, flag_groups = [flag_group(flags = ["-nostdlib", "--ld-path=" + ctx.file.linker.path])])]),
    ]
    return cc_common.create_cc_toolchain_config_info(
        ctx = ctx, features = features, action_configs = actions, cxx_builtin_include_directories = [],
        toolchain_identifier = "bsd-kernel-" + ctx.attr.cpu,
        host_system_name = "local", target_system_name = ctx.attr.target,
        target_cpu = ctx.attr.cpu, target_libc = "freestanding", compiler = "clang",
        abi_version = ctx.attr.target, abi_libc_version = "none",
    )

kernel_cc_config = rule(implementation = _impl, provides = [CcToolchainConfigInfo], attrs = {
    "target": attr.string(mandatory = True), "cpu": attr.string(mandatory = True),
    "cc_driver": attr.label(default = "@bsd_sdk//toolchain:bin/clang", allow_single_file = True, cfg = "exec"),
    "linker": attr.label(default = "@bsd_sdk//toolchain:bin/ld.lld", allow_single_file = True, cfg = "exec"),
    "archiver": attr.label(default = "@bsd_sdk//toolchain:bin/llvm-ar", allow_single_file = True, cfg = "exec"),
    "strip": attr.label(default = "@bsd_sdk//toolchain:bin/llvm-strip", allow_single_file = True, cfg = "exec"),
})
