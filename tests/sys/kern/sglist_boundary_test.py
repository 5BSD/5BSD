# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard

from atf_python.ktest import BaseKernelTest


class TestSglistBoundary(BaseKernelTest):
    """Run the in-kernel scatter/gather descriptor-boundary regressions."""

    KTEST_MODULE_NAME = "ktest_sglist_boundary"
