# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard

from atf_python.ktest import BaseKernelTest


class TestVirtioP9fsSglist(BaseKernelTest):
    """Run the in-kernel virtio 9P scatter list regressions."""

    KTEST_MODULE_NAME = "ktest_virtio_p9fs"
