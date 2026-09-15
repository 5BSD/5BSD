#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import sys
sys.dont_write_bytecode = True
from power_test import run_test
if __name__ == '__main__':
    run_test('clk_test.c', [
        ('sys/compat/linuxkpi/common/src/linux_clk.c', 'static void', 'lkpi_clk_release'),
        ('sys/compat/linuxkpi/common/src/linux_clk.c', 'struct linux_clk *',
         'linux_devm_clk_get_optional_enabled_with_rate'),
    ], ['-DFDT'])
