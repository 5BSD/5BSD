# SPDX-License-Identifier: BSD-2-Clause
"""Shared explicit overrides for native GENERIC configuration and source selectors."""
KERNEL_OPTION_SETTINGS = {
    Label("//tools/build/bazel/config:kernel_fdt"): "FDT",
    Label("//tools/build/bazel/config:kernel_zstdio"): "ZSTDIO",
    Label("//tools/build/bazel/config:kernel_nfs_root"): "NFS_ROOT",
    Label("//tools/build/bazel/config:kernel_tcp_hhook"): "TCP_HHOOK",
}

# Source-owned GENERIC defaults used by analysis-time selectors. Configuration
# generation verifies these against the actual parser headers before consumption.
KERNEL_OPTION_DEFAULTS = {
    "amd64": {"FDT": "no"},
    "arm64": {"FDT": "yes"},
    "riscv": {"FDT": "yes"},
}
KERNEL_ARCH_CPUS = {"amd64": "x86_64", "arm64": "aarch64", "riscv": "riscv64"}
