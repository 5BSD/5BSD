# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_python_test.bzl", "bsd_host_artifact_test")
load("//tools/build/bazel:bsd_kernel_module.bzl", "bsd_module_exports")

# Use actual target ELF artifacts. The negative provider reproduces the former
# Make default that localized the public MMC bus and bridge API.
def storage_bus_provider_tests(arch, modules, mmc_provider):
    bsd_host_artifact_test(
        name = arch + "_storage_bus_providers_test",
        src = "check.py",
        data = modules.values(),
        args = [arg for name, target in modules.items()
                for arg in ["--module", name + "=$(location " + target + ")"]] + [
            "--require-edge", 'mmcsd', 'mmc', 'mmc_send_ext_csd',
            "--require-edge", 'mmcsd', 'mmc', 'mmc_send_status',
            "--require-edge", 'mmcsd', 'mmc', 'mmc_switch',
            "--require-edge", 'mmcsd', 'mmc', 'mmc_wait_for_app_cmd',
            "--require-edge", 'mmcsd', 'mmc', 'mmc_wait_for_cmd',
            "--require-edge", 'rtsx', 'mmc', 'mmc_driver',
            "--require-edge", 'sdhci_pci', 'mmc', 'mmc_driver',
        ],
    )
    localized = arch + "_localized_mmc"
    bsd_module_exports(
        name = localized,
        src = mmc_provider,
        output = "negative/" + arch + "/mmc.local.kld",
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
        name = arch + "_localized_mmc_rejected_test",
        src = "check.py",
        data = [":" + localized, modules["mmcsd"], modules["rtsx"], modules["sdhci_pci"]],
        args = ["--expect-localized", "--module", "mmc=$(location :" + localized + ")"] + [
            arg for name in ["mmcsd", "rtsx", "sdhci_pci"]
            for arg in ["--module", name + "=$(location " + modules[name] + ")"]
        ],
    )
