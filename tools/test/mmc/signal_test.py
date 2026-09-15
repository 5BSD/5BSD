#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check the signal/wait contracts needed by the Linux SDIO watchdog."""
import sys
sys.dont_write_bytecode = True
from power_test import run_test

if __name__ == "__main__":
    functions = [
        ("bool", "linux_kthread_signal_pending"),
        ("int", "linux_allow_signal"),
        ("bool", "linux_task_prepare_interruptible"),
        ("void", "linux_task_finish_interruptible"),
        ("void", "linux_task_wake_interruptible"),
        ("void", "linux_send_sig"),
    ]
    run_test("signal_test.c", [
        ("sys/compat/linuxkpi/common/src/linux_schedule.c", result, name)
        for result, name in functions
    ] + [
        ("sys/compat/linuxkpi/common/src/linux_compat.c", "int", "linux_wait_for_common"),
    ], ["-pthread"])
