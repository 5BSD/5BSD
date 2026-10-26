# SPDX-License-Identifier: BSD-2-Clause
load("@bazel_tools//tools/cpp:cc_toolchain_config_lib.bzl", "feature", "flag_group", "flag_set", "tool_path")

_COMPILE = ["c-compile", "c++-compile", "assemble", "preprocess-assemble", "c++-header-parsing", "c++-module-compile", "c++-module-codegen"]
_LINK = ["c++-link-executable", "c++-link-dynamic-library", "c++-link-nodeps-dynamic-library"]

def _impl(ctx):
    root = "toolchain/sysroot"
    headers = [root + "/usr/include/c++/v1", root + "/usr/lib/clang/" + ctx.attr.clang_version + "/include", root + "/usr/include"]
    include_flags = ["-nostdinc"]
    for path in headers[1:]:
        include_flags.extend(["-isystem", path])
    features = [
        feature(name = "supports_pic", enabled = True),
        feature(name = "supports_dynamic_linker", enabled = True),
        feature(name = "pic", enabled = True, flag_sets = [flag_set(
            actions = _COMPILE,
            flag_groups = [flag_group(flags = ["-fPIC", "-DPIC"], expand_if_available = "pic")],
        )]),
        feature(name = "fully_static_link", flag_sets = [flag_set(
            actions = ["c++-link-executable"], flag_groups = [flag_group(flags = ["-static"])],
        )]),
        feature(name = "bsd_target", enabled = True, flag_sets = [flag_set(
            actions = _COMPILE + _LINK,
            flag_groups = [flag_group(flags = ["--target=" + ctx.attr.target, "--sysroot=" + root])],
        )]),
        # Sandboxed actions run in per-action directories; record a stable
        # DW_AT_comp_dir so debug output is reproducible across rebuilds.
        feature(name = "bsd_debug_compilation_dir", enabled = True, flag_sets = [flag_set(
            actions = _COMPILE, flag_groups = [flag_group(flags = ["-fdebug-compilation-dir=."])],
        )]),
        feature(name = "bsd_cpp_headers", enabled = True, flag_sets = [flag_set(
            actions = ["c++-compile", "c++-header-parsing", "c++-module-compile", "c++-module-codegen"],
            flag_groups = [flag_group(flags = ["-isystem", headers[0]])],
        )]),
        feature(name = "bsd_headers", enabled = True, flag_sets = [flag_set(
            actions = _COMPILE, flag_groups = [flag_group(flags = include_flags)],
        )]),
        feature(name = "bsd_linker", enabled = True, flag_sets = [flag_set(
            actions = _LINK,
            flag_groups = [flag_group(flags = ["--ld-path=toolchain/bin/ld.lld", "-Wl,-znow,-zrelro"])],
        )]),
    ]
    paths = {"gcc": "clang", "cpp": "clang", "ld": "ld.lld", "ar": "llvm-ar", "nm": "llvm-nm", "objcopy": "llvm-objcopy", "strip": "llvm-strip", "objdump": "llvm-objdump"}
    return cc_common.create_cc_toolchain_config_info(
        ctx = ctx,
        features = features,
        cxx_builtin_include_directories = headers,
        toolchain_identifier = "bsd-staged-clang",
        host_system_name = "local",
        target_system_name = ctx.attr.target,
        target_cpu = ctx.attr.cpu,
        target_libc = "freebsd",
        compiler = "clang",
        abi_version = ctx.attr.target,
        abi_libc_version = ctx.attr.target,
        tool_paths = [tool_path(name = name, path = "bin/" + path) for name, path in paths.items()],
    )

bsd_cc_config = rule(
    implementation = _impl,
    attrs = {"target": attr.string(mandatory = True), "cpu": attr.string(mandatory = True), "clang_version": attr.string(mandatory = True)},
    provides = [CcToolchainConfigInfo],
)

# This pilot exposes bounded static and shared primitives. Raw native rules using this
# experimental configuration are not a supported build-backend interface.
def bsd_static_binary(name, srcs, linkopts = [], linkshared = False, deps = [], copts = []):
    if linkshared:
        fail("BSD pilot supports static executables only")
    native.cc_binary(name = name, srcs = srcs, linkopts = linkopts, linkstatic = True, deps = deps, copts = copts, features = ["fully_static_link"])

def bsd_static_library(name, srcs, hdrs = [], deps = [], copts = []):
    native.cc_library(name = name, srcs = srcs, hdrs = hdrs, deps = deps, copts = copts, linkstatic = True)

def bsd_shared_library(name, soname, srcs, deps = [], copts = [], version_script = None):
    if not soname or "/" in soname or "," in soname:
        fail("explicit library basename required for SONAME")
    version_inputs = [version_script] if version_script else []
    version_flags = ["-Wl,--version-script=$(location " + version_script + "),--no-undefined-version"] if version_script else []
    native.cc_binary(name = name, srcs = srcs, deps = deps, copts = copts,
                     linkshared = True, linkstatic = True,
                     additional_linker_inputs = version_inputs,
                     linkopts = ["-Wl,-soname," + soname, "-Wl,--fatal-warnings,--warn-shared-textrel"] + version_flags)

def bsd_dynamic_binary(name, srcs, deps = [], copts = [], linkopts = []):
    native.cc_binary(name = name, srcs = srcs, deps = deps, linkstatic = False,
                     copts = copts + ["-fPIE"], linkopts = linkopts + ["-pie"])
