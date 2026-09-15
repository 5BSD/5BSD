#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import sys
sys.dont_write_bytecode = True
from power_test import run_test
if __name__ == '__main__':
    run_test('fullmac_bss_test.c', [
        ('sys/compat/linuxkpi/common/src/linux_80211_fullmac.c', 'static struct ieee80211vap *', 'lkpi_fullmac_vap_get'),
        ('sys/compat/linuxkpi/common/src/linux_80211_fullmac.c', 'struct ieee80211vap *', 'linuxkpi_fullmac_get_vap'),
        ('sys/compat/linuxkpi/common/src/linux_80211.c', 'struct cfg80211_bss *', 'linuxkpi_cfg80211_get_bss'),
    ])
