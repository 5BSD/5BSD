# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_python_test.bzl", "bsd_host_artifact_test")
load("//tools/build/bazel:bsd_kernel_module.bzl", "bsd_module_exports")

# Use actual target ELF artifacts. The negative provider reproduces the former
# Make default that localized the public TCP high-precision timer API.
def network_protocol_provider_tests(arch, modules, hpts_provider):
    bsd_host_artifact_test(
        name = arch + "_network_protocol_providers_test",
        src = "check.py",
        data = modules.values(),
        args = [arg for name, target in modules.items()
                for arg in ["--module", name + "=$(location " + target + ")"]] + [
            "--require-edge", 'tcp_bbr', "tcphpts", '__tcp_hpts_init',
            "--require-edge", 'tcp_bbr', "tcphpts", '__tcp_hpts_insert',
            "--require-edge", 'tcp_bbr', "tcphpts", '__tcp_hpts_remove',
            "--require-edge", 'tcp_bbr', "tcphpts", '__tcp_set_hpts',
            "--require-edge", 'tcp_bbr', "tcphpts", 'tcp_hptsi_pace',
            "--require-edge", 'tcp_bbr', "tcphpts", 'tcp_min_hptsi_time',
            "--require-edge", 'tcp_rack', "tcphpts", '__tcp_hpts_init',
            "--require-edge", 'tcp_rack', "tcphpts", '__tcp_hpts_insert',
            "--require-edge", 'tcp_rack', "tcphpts", '__tcp_hpts_remove',
            "--require-edge", 'tcp_rack', "tcphpts", '__tcp_set_hpts',
            "--require-edge", 'tcp_rack', "tcphpts", 'tcp_hptsi_pace',
            "--require-edge", 'tcp_rack', "tcphpts", 'tcp_min_hptsi_time',
        ],
    )
    localized = arch + "_localized_hpts"
    bsd_module_exports(
        name = localized,
        src = hpts_provider,
        output = "negative/" + arch + "/tcphpts.local.kld",
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
        name = arch + "_localized_hpts_rejected_test",
        src = "check.py",
        data = [":" + localized, modules["tcp_bbr"], modules["tcp_rack"]],
        args = ["--expect-localized", "--module", "tcphpts=$(location :" + localized + ")"] + [
            arg for name in ["tcp_bbr", "tcp_rack"]
            for arg in ["--module", name + "=$(location " + modules[name] + ")"]
        ],
    )
