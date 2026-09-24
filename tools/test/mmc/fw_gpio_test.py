#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check firmware GPIO readback against the mailbox state contract."""
from power_test import run_test

run_test("fw_gpio_test.c", [
    ("sys/arm/broadcom/bcm2835/raspberrypi_gpio.c", "static int", "rpi_fw_gpio_pin_get"),
])
