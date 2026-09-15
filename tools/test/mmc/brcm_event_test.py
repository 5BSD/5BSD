#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Parse real firmware wire structures and production event functions."""
import sys
import tempfile
from pathlib import Path
sys.dont_write_bytecode = True
from power_test import ROOT, run_test
if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='brcm-wire-') as directory:
        source = (ROOT / 'sys/contrib/dev/broadcom/brcm80211/brcmfmac/fweh.h').read_text()
        definitions = []
        for name in ['brcm_ethhdr', 'brcmf_event_msg_be', 'brcmf_event', 'brcmf_if_event']:
            start = source.index('struct ' + name + ' {')
            end = source.index(';', source.index('\n}', start)) + 1
            definitions.append(source[start:end])
        Path(directory, 'event_wire.h').write_text('\n'.join(definitions))
        run_test('brcm_event_test.c', [
            ('sys/contrib/dev/broadcom/brcm80211/brcmfmac/fweh.c', 'void', 'brcmf_fweh_process_event'),
            ('sys/contrib/dev/broadcom/brcm80211/brcmfmac/fweh.h', 'static inline void', 'brcmf_fweh_process_skb'),
        ], ['-I', directory])
