# SPDX-License-Identifier: BSD-2-Clause
"""Shared explicit overrides for native GENERIC configuration and source selectors."""
load("@bazel_skylib//rules:common_settings.bzl", "string_flag")
load("@bazel_skylib//lib:selects.bzl", "selects")

KERNEL_OPTION_SETTINGS = {
    Label("//tools/build/bazel/config:kernel_kdtrace_hooks"): "KDTRACE_HOOKS",
    Label("//tools/build/bazel/config:kernel_ipsec"): "IPSEC",
    Label("//tools/build/bazel/config:kernel_sctp_support"): "SCTP_SUPPORT",
    Label("//tools/build/bazel/config:kernel_sctp"): "SCTP",
    Label("//tools/build/bazel/config:kernel_inet"): "INET",
    Label("//tools/build/bazel/config:kernel_inet6"): "INET6",
    Label("//tools/build/bazel/config:kernel_fib_algo"): "FIB_ALGO",
    Label("//tools/build/bazel/config:kernel_mmccam"): "MMCCAM",
    Label("//tools/build/bazel/config:kernel_dev_acpi"): "DEV_ACPI",
    Label("//tools/build/bazel/config:kernel_mac"): "MAC",
    Label("//tools/build/bazel/config:kernel_ddb"): "DDB",
    Label("//tools/build/bazel/config:kernel_vimage"): "VIMAGE",
    Label("//tools/build/bazel/config:kernel_smp"): "SMP",
    Label("//tools/build/bazel/config:kernel_kcsan"): "KCSAN",

    Label("//tools/build/bazel/config:kernel_ipsec_support"): "IPSEC_SUPPORT",
    Label("//tools/build/bazel/config:kernel_tcp_signature"): "TCP_SIGNATURE",
    Label("//tools/build/bazel/config:kernel_fdt"): "FDT",
    Label("//tools/build/bazel/config:kernel_zstdio"): "ZSTDIO",
    Label("//tools/build/bazel/config:kernel_nfs_root"): "NFS_ROOT",
    Label("//tools/build/bazel/config:kernel_tcp_hhook"): "TCP_HHOOK",
}

# Source-owned GENERIC defaults used by analysis-time selectors. Configuration
# generation verifies these against the actual parser headers before consumption.
KERNEL_OPTION_DEFAULTS = {
    "amd64": {"KDTRACE_HOOKS": "yes", "IPSEC": "no", "SCTP_SUPPORT": "yes", "SCTP": "no", "INET": "yes", "INET6": "yes", "FIB_ALGO": "yes", "MMCCAM": "no", "DEV_ACPI": "yes", "MAC": "yes", "DDB": "yes", "VIMAGE": "yes", "SMP": "yes", "KCSAN": "no", "IPSEC_SUPPORT": "yes", "TCP_SIGNATURE": "no", "FDT": "no"},
    "arm64": {"KDTRACE_HOOKS": "yes", "IPSEC": "no", "SCTP_SUPPORT": "yes", "SCTP": "no", "INET": "yes", "INET6": "yes", "FIB_ALGO": "yes", "MMCCAM": "no", "DEV_ACPI": "yes", "MAC": "yes", "DDB": "yes", "VIMAGE": "yes", "SMP": "yes", "KCSAN": "no", "IPSEC_SUPPORT": "yes", "TCP_SIGNATURE": "no", "FDT": "yes"},
    "riscv": {"KDTRACE_HOOKS": "yes", "IPSEC": "no", "SCTP_SUPPORT": "yes", "SCTP": "no", "INET": "yes", "INET6": "yes", "FIB_ALGO": "yes", "MMCCAM": "no", "DEV_ACPI": "no", "MAC": "yes", "DDB": "yes", "VIMAGE": "yes", "SMP": "yes", "KCSAN": "no", "IPSEC_SUPPORT": "yes", "TCP_SIGNATURE": "no", "FDT": "yes"},
}
KERNEL_ARCH_CPUS = {"amd64": "x86_64", "arm64": "aarch64", "riscv": "riscv64"}

def kernel_option_setting(name, option):
    """Declare auto/yes/no selectors from the same checked source defaults."""
    string_flag(name = name, build_setting_default = "auto", values = ["auto", "yes", "no"],
        visibility = ["//visibility:public"])
    for value in ["yes", "no"]:
        native.config_setting(name = name + "_" + value, flag_values = {":" + name: value})
    for arch in sorted(KERNEL_OPTION_DEFAULTS):
        native.config_setting(name = name + "_auto_" + arch,
            flag_values = {":" + name: "auto"},
            constraint_values = ["@platforms//cpu:" + KERNEL_ARCH_CPUS[arch]])
    for value, suffix in [("yes", "enabled"), ("no", "disabled")]:
        selects.config_setting_group(name = name + "_" + suffix, match_any = [":" + name + "_" + value] +
            [":" + name + "_auto_" + arch for arch in sorted(KERNEL_OPTION_DEFAULTS)
             if KERNEL_OPTION_DEFAULTS[arch][option] == value], visibility = ["//visibility:public"])

# Device statements generate DEV_* symbols but need native device directives.
KERNEL_DEVICE_OPTIONS = {"DEV_ACPI": "acpi"}
