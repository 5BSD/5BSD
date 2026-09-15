#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Inject failures into real cfg80211 and bus attach paths."""
import sys
sys.dont_write_bytecode = True
from power_test import run_test
if __name__ == '__main__':
    run_test('brcm_attach_test.c', [
        ('sys/contrib/dev/broadcom/brcm80211/brcmfmac/cfg80211.c',
         'struct brcmf_cfg80211_info *', 'brcmf_cfg80211_attach'),
        ('sys/contrib/dev/broadcom/brcm80211/brcmfmac/core.c',
         'static int', 'brcmf_bus_started'),
        ('sys/contrib/dev/broadcom/brcm80211/brcmfmac/core.c',
         'void', 'brcmf_detach'),
    ])
