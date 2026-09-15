#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise shared SDIO driver lifetime with asynchronous firmware callbacks."""
import sys
sys.dont_write_bytecode = True
from power_test import run_test

if __name__ == '__main__':
    run_test('sdio_lifetime_test.c', [
        ('sys/compat/linuxkpi/common/src/linux_sdio.c', result, name)
        for result, name in [
            ('static void', 'lkpi_sdio_unbind_pending'),
            ('static void', 'lkpi_sdio_schedule_unbind'),
            ('static void', 'lkpi_sdio_unbind_task'),
            ('static int', 'lkpi_sdio_async_get'),
            ('static void', 'lkpi_sdio_async_put'),
            ('static void', 'lkpi_sdio_release_driver'),
            ('static int', 'lkpi_sdio_detach'),
            ('static int', 'lkpi_sdio_driver_busy'),
            ('static int', 'lkpi_sdio_delete_driver'),
            ('int', 'linux_sdio_module_event'),
            ('void', 'linux_sdio_unregister_driver'),
            ('static int', 'lkpi_sdio_modevent'),
        ]
    ])
