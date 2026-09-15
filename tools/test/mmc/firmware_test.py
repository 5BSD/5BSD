#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check asynchronous firmware ownership and failure semantics."""
import sys
sys.dont_write_bytecode = True
from power_test import run_test

if __name__ == "__main__":
    run_test("firmware_test.c", [
        ("sys/compat/linuxkpi/common/src/linux_firmware.c", result, name)
        for result, name in [
            ("static int", "lkpi_fw_module_hold"),
            ("static void", "lkpi_fw_module_put"),
            ("static int", "_linuxkpi_request_firmware"),
            ("static void", "lkpi_fw_task"),
            ("int", "linuxkpi_request_firmware_nowait"),
        ]
    ])
