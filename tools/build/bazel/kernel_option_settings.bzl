# SPDX-License-Identifier: BSD-2-Clause
"""Shared explicit overrides for native GENERIC configuration and source selectors."""
KERNEL_OPTION_SETTINGS = {
    Label("//tools/build/bazel/config:kernel_zstdio"): "ZSTDIO",
    Label("//tools/build/bazel/config:kernel_nfs_root"): "NFS_ROOT",
    Label("//tools/build/bazel/config:kernel_tcp_hhook"): "TCP_HHOOK",
}
