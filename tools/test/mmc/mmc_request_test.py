#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Validate LinuxKPI MMC requests before consuming an SDIO FIFO."""
import sys
sys.dont_write_bytecode = True
from power_test import run_test

if __name__ == '__main__':
    run_test('mmc_request_test.c', [
        ('sys/compat/linuxkpi/common/src/linux_sdio.c',
         'void', 'linux_mmc_wait_for_req'),
    ])
