#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Fault-inject the real Broadcom host attach path used by Pi SDIO."""
import sys
sys.dont_write_bytecode = True
from power_test import run_test
if __name__ == '__main__':
    run_test('bcm_host_attach_test.c', [
        ('sys/arm/broadcom/bcm2835/bcm2835_sdhci.c', 'static int', 'bcm_sdhci_attach'),
    ])
