#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise native SDIO commands with fake CAM and real competing threads."""
import sys
sys.dont_write_bytecode = True
from power_test import run_test

if __name__ == "__main__":
    bus_functions = [
        ("static int", "sdiob_cmd_error"),
        ("static void", "sdiob_claim_host"),
        ("static void", "sdiob_release_host"),
        ("static int", "sdiob_rw_direct_sc"),
        ("static int", "sdio_rw_direct"),
        ("static int", "sdiob_read_direct"),
        ("static int", "sdiob_write_direct"),
        ("static int", "sdiob_rw_extended_cam"),
        ("static int", "sdiob_rw_extended_sc"),
        ("static int", "sdiob_rw_extended"),
    ]
    subr_functions = [
        ("void", "sdio_claim_host"),
        ("void", "sdio_release_host"),
        ("static int", "sdio_set_bool_for_func"),
        ("int", "sdio_enable_func"),
        ("int", "sdio_set_block_size"),
    ]
    run_test("sdio_test.c", [
        ("sys/dev/sdio/sdiob.c", result, name) for result, name in bus_functions
    ] + [
        ("sys/dev/sdio/sdio_subr.c", result, name) for result, name in subr_functions
    ], ["-pthread"])
