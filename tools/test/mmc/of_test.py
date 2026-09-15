#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check bounded OF property reads and ownership of node snapshots."""
import sys
sys.dont_write_bytecode = True
from power_test import run_test

if __name__ == "__main__":
    run_test("of_test.c", [
        ("sys/compat/linuxkpi/common/src/linux_of.c", result, name)
        for result, name in [
            ("struct device_node *", "linux_of_node_get"),
            ("void", "linux_of_node_put"),
            ("struct device_node *", "linux_of_node_from_handle"),
            ("const void *", "linux_of_get_property"),
            ("int", "linux_of_property_read_string_index"),
            ("int", "linux_of_property_count_strings"),
            ("int", "linux_of_property_read_u32"),
            ("bool", "linux_of_device_is_compatible"),
            ("int", "linux_of_get_mac_address"),
        ]
    ], ["-DFDT", "-D_POSIX_C_SOURCE=200809L"])
