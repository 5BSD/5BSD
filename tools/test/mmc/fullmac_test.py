#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check FullMAC teardown, canceled scan completion and RSN validation."""
import sys
sys.dont_write_bytecode = True
from power_test import run_test

if __name__ == '__main__':
    run_test('fullmac_test.c', [
        ('sys/compat/linuxkpi/common/src/linux_80211_fullmac.c', result, name)
        for result, name in [
            ('static void', 'lkpi_fullmac_tx_task'),
            ('static int', 'lkpi_fullmac_transmit'),
            ('static void', 'lkpi_fullmac_vap_delete'),
            ('static void', 'lkpi_fullmac_scan_end'),
            ('void', 'linuxkpi_fullmac_scan_done'),
            ('static int', 'lkpi_fullmac_rsn'),
        ]
    ])
    run_test('fullmac_create_test.c', [
        ('sys/compat/linuxkpi/common/src/linux_80211_fullmac.c',
         'static struct ieee80211vap *', 'lkpi_fullmac_vap_create'),
        ('sys/compat/linuxkpi/common/src/linux_80211_fullmac.c',
         'static void', 'lkpi_fullmac_unregister'),
    ], flags=['-pthread'])
    run_test('brcm_scan_test.c', [
        ('sys/contrib/dev/broadcom/brcm80211/brcmfmac/cfg80211.c', result, name)
        for result, name in [
            ('static s32', 'brcmf_notify_escan_complete_locked'),
            ('s32', 'brcmf_notify_escan_complete'),
            ('u16', 'brcmf_escan_begin'),
            ('static bool', 'brcmf_bss_valid'),
            ('static void', 'brcmf_abort_scanning_locked'),
            ('void', 'brcmf_cfg80211_scan_quiesce'),
            ('static s32', 'brcmf_cfg80211_scan_locked'),
            ('static s32', 'brcmf_cfg80211_scan'),
            ('static void', 'brcmf_cfg80211_escan_timeout_worker'),
            ('static void', 'brcmf_escan_timeout'),
            ('static s32', 'brcmf_cfg80211_escan_handler_locked'),
            ('static s32', 'brcmf_cfg80211_escan_handler'),
        ]
    ], flags=['-pthread'])
