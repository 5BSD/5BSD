#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise LinuxKPI kthread return/join ownership against production bodies."""
import sys
sys.dont_write_bytecode = True
from power_test import run_test

if __name__ == "__main__":
    run_test("kthread_test.c", [
        ("sys/compat/linuxkpi/common/src/linux_kthread.c", result, name)
        for result, name in [
            ("bool", "linux_kthread_should_stop_task"),
            ("int", "linux_kthread_stop"),
            ("struct task_struct *", "linux_kthread_setup_and_run"),
            ("void", "linux_kthread_fn"),
        ]
    ], ["-pthread"])
