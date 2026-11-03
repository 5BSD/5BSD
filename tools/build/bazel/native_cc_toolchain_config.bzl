# SPDX-License-Identifier: BSD-2-Clause
load("@rules_cc//cc:cc_toolchain_config_lib.bzl", "action_config", "tool", "feature", "flag_group", "flag_set", "tool_path", "with_feature_set")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc:action_names.bzl", "ACTION_NAMES")
load("@rules_cc//cc/toolchains:cc_toolchain_config_info.bzl", "CcToolchainConfigInfo")
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")

_COMPILE = ["c-compile", "c++-compile", "assemble", "preprocess-assemble", "c++-header-parsing", "c++-module-compile", "c++-module-codegen"]
_LINK = ["c++-link-executable", "c++-link-dynamic-library", "c++-link-nodeps-dynamic-library"]


def _impl(ctx):
    # Label roots include the canonical external-repository path when needed.
    # The SDK layout is package-relative; its workspace location is not fixed.
    package_root = "/".join([part for part in [ctx.label.workspace_root, ctx.label.package] if part])
    root = (package_root + "/" if package_root else "") + "sysroot"
    linker = (package_root + "/" if package_root else "") + "bin/ld.lld"
    headers = [root + "/usr/include/c++/v1", root + "/usr/lib/clang/" + ctx.attr.clang_version + "/include", root + "/usr/include"]
    features = [
        feature(name = "opt", flag_sets = [flag_set(
            actions = _COMPILE, flag_groups = [flag_group(flags = ["-O2"])],
        )]),
        feature(name = "dbg", flag_sets = [flag_set(
            actions = _COMPILE, flag_groups = [flag_group(flags = ["-O0"])],
        )]),
        feature(name = "fastbuild", flag_sets = [flag_set(
            actions = _COMPILE, flag_groups = [flag_group(flags = ["-O0"])],
        )]),
        # Base builds retain DWARF for separate debug packages, including opt.
        feature(name = "bsd_debug_info", enabled = True, flag_sets = [flag_set(
            actions = _COMPILE, flag_groups = [flag_group(flags = ["-g", "-gz=zlib"])],
        )]),
        # Base defaults from bsd.opts.mk, modeled as selectable toolchain
        # features rather than duplicated component link flags.
        # Match MK_SSP's Clang userland default. Compiler-specific stack-clash
        # flags and freestanding/kernel policy require their own toolchains.
        feature(name = "bsd_ssp", enabled = True, flag_sets = [flag_set(
            actions = ["c-compile", "c++-compile", "c++-module-compile", "c++-module-codegen"],
            flag_groups = [flag_group(flags = ["-fstack-protector-strong"])],
        )]),
        feature(name = "bsd_bind_now", enabled = True),
        feature(name = "bsd_relro", enabled = True),
        feature(name = "bsd_elf_security", enabled = True, flag_sets = [
            flag_set(actions = _LINK, with_features = [with_feature_set(features = ["bsd_bind_now"])],
                     flag_groups = [flag_group(flags = ["-Wl,-z,now"])]),
            flag_set(actions = _LINK, with_features = [with_feature_set(not_features = ["bsd_bind_now"])],
                     flag_groups = [flag_group(flags = ["-Wl,-z,lazy"])]),
            flag_set(actions = _LINK, with_features = [with_feature_set(features = ["bsd_relro"])],
                     flag_groups = [flag_group(flags = ["-Wl,-z,relro"])]),
            flag_set(actions = _LINK, with_features = [with_feature_set(not_features = ["bsd_relro"])],
                     flag_groups = [flag_group(flags = ["-Wl,-z,norelro"])]),
        ]),
        # Installed BSD binaries use maintained LDFLAGS for runtime paths.
        # Override the legacy injected feature so it cannot add Bazel runfiles.
        feature(name = "runtime_library_search_directories", enabled = True),
        # Tests execute declared build outputs; installed artifacts keep their
        # configured system paths. Opt in only on runnable qualification targets.
        feature(name = "bsd_test_runtime_paths", flag_sets = [flag_set(
            actions = ["c++-link-executable"],
            flag_groups = [flag_group(
                iterate_over = "runtime_library_search_directories",
                expand_if_available = "runtime_library_search_directories",
                flags = ["-Wl,-rpath,$ORIGIN/%{runtime_library_search_directories}"],
            )],
        )]),
        feature(name = "supports_pic", enabled = True),
        feature(name = "supports_dynamic_linker", enabled = True),
        # Make SHARED_CFLAGS=-fpic has PIC level 1. Opt in per library;
        # ordinary objects and existing large-PIC callers keep their flags.
        feature(name = "bsd_small_pic"),
        feature(name = "pic", enabled = True, flag_sets = [
            flag_set(actions = _COMPILE,
                with_features = [with_feature_set(not_features = ["bsd_small_pic"])],
                flag_groups = [flag_group(flags = ["-fPIC", "-DPIC"], expand_if_available = "pic")]),
            flag_set(actions = _COMPILE,
                with_features = [with_feature_set(features = ["bsd_small_pic"])],
                flag_groups = [flag_group(flags = ["-fpic", "-DPIC"], expand_if_available = "pic")]),
        ]),
        # OpenSSL's maintained SHARED_CFLAGS applies only to PIC objects.
        # Targets opt in; ordinary base libraries receive no OpenSSL defines.
        feature(name = "bsd_openssl_pic", flag_sets = [flag_set(
            actions = _COMPILE,
            flag_groups = [flag_group(flags = ["-DOPENSSL_PIC"], expand_if_available = "pic")],
        )]),
        # libarchive's BSD iconv support is currently a shared-object-only option.
        feature(name = "bsd_libarchive_iconv", flag_sets = [flag_set(
            actions = _COMPILE,
            flag_groups = [flag_group(flags = ["-DHAVE_ICONV=1", "-DHAVE_ICONV_H=1", "-DICONV_CONST="],
                expand_if_available = "pic")],
        )]),
        feature(name = "fully_static_link", flag_sets = [flag_set(
            actions = ["c++-link-executable"], flag_groups = [flag_group(flags = ["-static"])],
        )]),
        feature(name = "bsd_target", enabled = True, flag_sets = [flag_set(
            actions = _COMPILE + _LINK,
            flag_groups = [flag_group(flags = ["--target=" + ctx.attr.target, "--sysroot=" + root])],
        )]),
        # Let the selected FreeBSD driver order C++/builtin/C headers and
        # honor -nostdinc/-nostdinc++/-nostdlibinc. Both its system root and
        # resource directory point at declared staged toolchain inputs.
        feature(name = "bsd_headers", enabled = True, flag_sets = [flag_set(
            actions = _COMPILE,
            flag_groups = [flag_group(flags = ["-resource-dir=" + root + "/usr/lib/clang/" + ctx.attr.clang_version])],
        )]),
        # FreeBSD does not provide Linux's /proc/self/cwd convention. Clang
        # otherwise records each transient sandbox path in DWARF, changing
        # artifacts when identical inputs run in a different action sandbox.
        feature(name = "bsd_stable_debug_directory", enabled = True, flag_sets = [flag_set(
            actions = _COMPILE,
            flag_groups = [flag_group(flags = ["-fdebug-compilation-dir=."])],
        )]),
        feature(name = "bsd_linker", enabled = True, flag_sets = [flag_set(
            actions = _LINK,
            flag_groups = [flag_group(flags = ["--ld-path=" + linker])],
        )]),
    ]
    validation_actions = []
    if ctx.attr.archive_validation:
        features.append(feature(name = "symbol_check", implies = [ACTION_NAMES.validate_static_library]))
        validation_actions.append(action_config(
            action_name = ACTION_NAMES.validate_static_library,
            enabled = False,
            tools = [tool(path = "bin/validate_static_library")],
        ))
    paths = {"gcc": "clang", "cpp": "clang", "ld": "ld.lld", "ar": "llvm-ar", "nm": "llvm-nm", "objcopy": "llvm-objcopy", "strip": "llvm-strip", "objdump": "llvm-objdump"}
    return cc_common.create_cc_toolchain_config_info(
        ctx = ctx,
        features = features,
        action_configs = validation_actions,
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
    attrs = {"target": attr.string(mandatory = True), "cpu": attr.string(mandatory = True), "clang_version": attr.string(mandatory = True), "archive_validation": attr.bool(default = False)},
    provides = [CcToolchainConfigInfo],
)

# This pilot exposes bounded static and shared primitives. Raw native rules using this
# experimental configuration are not a supported build-backend interface.
def bsd_static_binary(name, srcs, linkopts = [], linkshared = False, deps = [], copts = []):
    if linkshared:
        fail("BSD pilot supports static executables only")
    cc_binary(name = name, srcs = srcs, linkopts = linkopts, linkstatic = True, deps = deps, copts = copts, features = ["fully_static_link"])

def bsd_static_library(name, srcs, hdrs = [], deps = [], copts = []):
    cc_library(name = name, srcs = srcs, hdrs = hdrs, deps = deps, copts = copts, linkstatic = True)

def bsd_shared_library(name, soname, srcs, deps = [], copts = [], version_script = None):
    if not soname or "/" in soname or "," in soname:
        fail("explicit library basename required for SONAME")
    version_inputs = [version_script] if version_script else []
    version_flags = ["-Wl,--version-script=$(location " + version_script + "),--no-undefined-version"] if version_script else []
    cc_binary(name = name, srcs = srcs, deps = deps, copts = copts,
                     linkshared = True, linkstatic = True,
                     additional_linker_inputs = version_inputs,
                     linkopts = ["-Wl,-soname," + soname, "-Wl,--fatal-warnings,--warn-shared-textrel"] + version_flags)

def bsd_dynamic_binary(name, srcs, deps = [], copts = [], linkopts = []):
    cc_binary(name = name, srcs = srcs, deps = deps, linkstatic = False,
                     copts = copts + ["-fPIE"], linkopts = linkopts + ["-pie"])
