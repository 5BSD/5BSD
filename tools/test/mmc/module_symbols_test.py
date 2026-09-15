#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check module exports in make inputs and, optionally, built ELF artifacts.

Example: python3 tools/test/mmc/module_symbols_test.py --artifacts /path/to/if_brcmfmac.ko \
/path/to/linuxkpi.ko /path/to/linuxkpi_sdio.ko /path/to/linuxkpi_wlan.ko /path/to/brcmutil.ko

The ELF check verifies Wi-Fi stack imports, not the entire kernel ABI.
"""
import argparse
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]

def symbols(path):
    defined, undefined = set(), set()
    for line in subprocess.check_output(['nm', '-g', str(path)], text=True).splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        kind, name = parts[-2:]
        if kind == 'U':
            undefined.add(name)
        elif kind in 'TDBRWVAi':
            defined.add(name)
    return defined, undefined

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', nargs='+', type=Path)
    parser.add_argument('--kernel', type=Path, help='also resolve every strong import against this kernel')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='rpi-export-test-') as directory:
        for module in ['linuxkpi_sdio', 'brcm80211/brcmutil']:
            value = subprocess.check_output(['make', '-C', str(ROOT / 'sys/modules' / module),
                'MACHINE=arm64', 'MACHINE_ARCH=aarch64', 'KERN_OPTS=MMCCAM FDT DEV_CLK',
                '-V', 'EXPORT_SYMS'], env=dict(os.environ, MAKEOBJDIR=directory), text=True).strip()
            assert value == 'YES', f'{module} hides APIs needed by brcmfmac: EXPORT_SYMS={value}'
    print('PASS: provider modules retain their public APIs')
    if args.artifacts:
        exports, imports = set(), set()
        for path in args.artifacts:
            defined, undefined = symbols(path)
            exports.update(defined)
            imports.update(undefined)
        # Native kernel symbols are outside this check. These prefixes belong
        # exclusively to the modules supplying the imported SDIO driver.
        prefixes = ('brcmu_', 'brcmf_', 'linux_sdio_', 'linux_mmc_',
                    'linuxkpi_fullmac_', 'linux_devm_clk_', 'linux_of_')
        missing = sorted(s for s in imports - exports if s.startswith(prefixes))
        assert not missing, 'Unresolved Wi-Fi module imports: ' + ', '.join(missing)
        assert any(s.startswith('linux_sdio_') for s in imports), 'No SDIO consumer supplied'
        print('PASS: built ELF modules resolve Wi-Fi/SDIO/OF/clock imports across providers')

        if args.kernel:
            exports.update(symbols(args.kernel)[0])
            # kern_linker.c synthesizes this per-module value at load time.
            missing = sorted(imports - exports - {'__this_linker_file'})
            assert not missing, 'Unresolved kernel/module imports: ' + ', '.join(missing)
            print('PASS: every strong module import resolves against the kernel and supplied providers')
