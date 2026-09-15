#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check the actual make/config inputs used to build the Pi SDIO stack."""
from pathlib import Path
import os
import subprocess
import tempfile
ROOT = Path(__file__).resolve().parents[3]
with tempfile.TemporaryDirectory(prefix='rpi-integration-') as directory:
    obj = Path(directory)
    env = dict(os.environ, MAKEOBJDIR=str(obj))
    def make_value(module, options, variable):
        return subprocess.check_output([
            'make', '-C', str(ROOT / 'sys/modules' / module),
            'MACHINE=arm64', 'MACHINE_ARCH=aarch64', 'KERN_OPTS='+options,
            '-V', variable], env=env, text=True).split()
    options = 'MMCCAM FDT DEV_CLK'
    modules = make_value('', options, 'SUBDIR')
    assert 'brcm80211' in modules and 'linuxkpi_sdio' in modules
    modules = make_value('', 'FDT DEV_CLK', 'SUBDIR')
    assert 'brcm80211' not in modules and 'linuxkpi_sdio' not in modules
    sources = make_value('brcm80211/brcmfmac', options, 'SRCS')
    assert all(p in sources for p in ['sdio.c', 'bcmsdh.c', 'sdio_module.c', 'of.c'])
    assert 'pcie.c' not in sources
    kernel = obj / 'kernel'
    kernel.mkdir()
    subprocess.run(['config', '-d', str(kernel), str(ROOT / 'sys/arm64/conf/VBSD-RPI')],
                   cwd=ROOT / 'sys/arm64/conf', check=True, stdout=subprocess.DEVNULL)
    config = (kernel / 'config.c').read_text() if (kernel / 'config.c').exists() else ''
    # The generated kernel makefile must use the CAM SDIO bus and Linux bridge.
    makefile = (kernel / 'Makefile').read_text()
    assert 'sdiob.c' in makefile
    # Syntax validation also catches quoting errors in the image gate/loader entry.
    subprocess.run(['sh', '-n', str(ROOT / 'release/tools/rpi4-zfs.conf')], check=True)
print('PASS: MMCCAM module selection, SDIO-only driver sources and Raspberry Pi kernel configuration')
