#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import sys
sys.dont_write_bytecode = True
from power_test import run_test
if __name__ == '__main__':
    run_test('fullmac_key_test.c', [
        ('sys/compat/linuxkpi/common/src/linux_80211_fullmac.c', result, name)
        for result, name in [
            ('static void', 'lkpi_fullmac_key_enter'),
            ('static void', 'lkpi_fullmac_key_leave'),
            ('static int', 'lkpi_fullmac_key_alloc'),
            ('static int', 'lkpi_fullmac_key_set'),
            ('static int', 'lkpi_fullmac_key_delete'),
        ]
    ])
