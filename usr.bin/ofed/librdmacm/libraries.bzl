# SPDX-License-Identifier: BSD-2-Clause
"""Shared example link contract from librdmacm/Makefile.inc."""
RDMA_EXAMPLE_LIBRARIES = [
    "//lib/ofed/libibverbs:ibverbs",
    "//lib/ofed/librdmacm:rdmacm",
    "//lib/ofed/libirdma:irdma",
    "//lib/ofed/libmlx4:mlx4",
    "//lib/ofed/libmlx5:mlx5",
    "//lib/ofed/libbnxtre:bnxtre",
    "//lib/ofed/libcxgb4:cxgb4",
    "//lib/libthr:thr",
]
RDMA_EXAMPLE_SHARED_LIBRARIES = [library + "_shared" for library in RDMA_EXAMPLE_LIBRARIES]
