#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import re
import sys
import tempfile
from pathlib import Path
sys.dont_write_bytecode = True
from power_test import ROOT, run_test
if __name__ == '__main__':
    cfg = (ROOT / 'sys/compat/linuxkpi/common/include/net/cfg80211.h').read_text()
    nl = (ROOT / 'sys/compat/linuxkpi/common/include/linux/nl80211.h').read_text()
    struct = re.search(r'struct cfg80211_crypto_settings \{.*?\n};', cfg, re.S).group()
    with tempfile.TemporaryDirectory(prefix='rpi-crypto-') as d:
        header = 'enum nl80211_wpa_versions { NL80211_WPA_VERSION_2 = 2 };\n'
        for text, name in [(nl, 'NL80211_MAX_NR_CIPHER_SUITES'), (cfg, 'CFG80211_MAX_NUM_AKM_SUITES')]:
            header += re.search(r'^#define\s+' + name + r'\s+\d+', text, re.M).group() + '\n'
        (Path(d) / 'crypto_layout.h').write_text(header + struct)
        run_test('crypto_layout_test.c', [
            ('sys/contrib/dev/broadcom/brcm80211/brcmfmac/cfg80211.c', 'static s32', 'brcmf_set_wsec_mode')
        ], ['-I', d, '-fsanitize=address,undefined'])
