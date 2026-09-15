#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise firmware event shutdown using production functions and pthreads."""
import sys
sys.dont_write_bytecode = True
from power_test import run_test
if __name__ == '__main__':
    run_test('brcm_lifetime_test.c', [
        ('sys/contrib/dev/broadcom/brcm80211/brcmfmac/fweh.c', result, name)
        for result, name in [
            ('static void', 'brcmf_fweh_queue_event'),
            ('static struct brcmf_fweh_queue_item *', 'brcmf_fweh_dequeue_event'),
            ('void', 'brcmf_fweh_quiesce'),
        ]
    ], flags=['-pthread'])
