#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import sys
sys.dont_write_bytecode = True
from power_test import run_test
if __name__ == '__main__':
    run_test('fullmac_rx_test.c', [
        ('sys/compat/linuxkpi/common/include/linux/etherdevice.h', 'static inline uint16_t', 'eth_type_trans'),
        ('sys/compat/linuxkpi/common/src/linux_80211_fullmac.c', 'static void', 'lkpi_fullmac_rx'),
    ])
