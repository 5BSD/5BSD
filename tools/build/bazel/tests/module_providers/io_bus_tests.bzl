# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_python_test.bzl", "bsd_host_artifact_test")
load("//tools/build/bazel:bsd_kernel_module.bzl", "bsd_module_exports")

# Use actual target ELF artifacts. The negative provider reproduces the former
# Make default that localized public 1-Wire KOBJ method descriptors.
def io_bus_provider_tests(arch, modules, ow_provider):
    bsd_host_artifact_test(
        name = arch + "_io_bus_providers_test",
        src = "check.py",
        data = modules.values(),
        args = [arg for name, target in modules.items()
                for arg in ["--module", name + "=$(location " + target + ")"]] + [
            "--require-edge", "ow_temp", "ow", "own_acquire_bus_desc",
            "--require-edge", "ow_temp", "ow", "own_crc_desc",
            "--require-edge", "ow_temp", "ow", "own_release_bus_desc",
            "--require-edge", "ow_temp", "ow", "own_send_command_desc",
            "--require-edge", "owc", "ow", "owll_read_data_desc",
            "--require-edge", "owc", "ow", "owll_reset_and_presence_desc",
            "--require-edge", "owc", "ow", "owll_write_one_desc",
            "--require-edge", "owc", "ow", "owll_write_zero_desc",
        ],
    )
    localized = arch + "_localized_ow"
    bsd_module_exports(
        name = localized,
        src = ow_provider,
        output = "negative/" + arch + "/ow.local.kld",
        exports = [],
        nm = "@bsd_sdk//toolchain:bin/llvm-nm",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy",
        tool_inputs = ["@bsd_sdk//toolchain:llvm-nm_runtime", "@bsd_sdk//toolchain:objcopy_inputs"],
        redirect = "@bsd_sdk//toolchain:stdout_redirect",
        libraries = ["//lib/msun:m_shared", "@bsd_sdk//toolchain:sysroot/lib/libc.so.7", "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7"],
        python = "@bsd_sdk//toolchain:extra_python",
        python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib"],
    )
    bsd_host_artifact_test(
        name = arch + "_localized_ow_rejected_test",
        src = "check.py",
        data = [":" + localized, modules["ow_temp"], modules["owc"]],
        args = ["--expect-localized", "--module", "ow=$(location :" + localized + ")"] + [
            arg for name in ["ow_temp", "owc"]
            for arg in ["--module", name + "=$(location " + modules[name] + ")"]
        ],
    )
