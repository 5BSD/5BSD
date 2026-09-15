#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import sys
sys.dont_write_bytecode = True
from power_test import run_test
if __name__ == '__main__':
    run_test('brcm_bus_stop_test.c', [
        ('sys/contrib/dev/broadcom/brcm80211/brcmfmac/sdio.c',
         'static void', 'brcmf_sdio_bus_stop'),
    ])
