#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Validate Pi Wi-Fi SDT declarations, script compilation and lifecycle events."""
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
sys.dont_write_bytecode = True
from power_test import ROOT, run_test

SOURCES = [
    'sys/dev/sdio/sdiob.c',
    'sys/arm/broadcom/bcm2835/bcm2835_sdhci.c',
    *['sys/compat/linuxkpi/common/src/' + n for n in
      ('linux_sdio.c', 'linux_firmware.c', 'linux_80211_fullmac.c')],
]


def declarations_test():
    definitions, calls = {}, set()
    disabled = ['#include <sys/param.h>', '#include <sys/queue.h>',
                '#undef KDTRACE_HOOKS', f'#include "{ROOT}/sys/sys/sdt.h"']
    for path in SOURCES:
        source = (ROOT / path).read_text()
        disabled += re.findall(r'SDT_PROVIDER_DEFINE\([^;]+;', source)
        for match in re.finditer(r'SDT_PROBE_DEFINE(\d)\((\w+),\s*(\w+),\s*,\s*(\w+),([^;]+);', source):
            count, provider, module, name, types = match.groups()
            key = provider, module, name
            assert key not in definitions, key
            assert len(re.findall(r'"[^"]+"', types)) == int(count)
            definitions[key] = int(count)
            disabled.append(match.group())
        for count, provider, module, name in re.findall(
                r'SDT_PROBE(\d)\((\w+),\s*(\w+),\s*,\s*(\w+),', source):
            key = provider, module, name
            assert definitions[key] == int(count), key
            calls.add(key)
    assert calls == definitions.keys()
    script = (ROOT / 'share/dtrace/rpi-wifi').read_text()
    for provider, name in re.findall(r'^(\w+):::([\w-]+)', script, re.M):
        assert any(p == provider and n.replace('__', '-') == name
                   for p, m, n in definitions), (provider, name)
    # Disabled kernel probes must neither reference nor evaluate their arguments.
    disabled.append('void test_disabled(void) {')
    for (provider, module, name), count in definitions.items():
        disabled.append(f'SDT_PROBE{count}({provider}, {module}, , {name}, ' +
                        ', '.join(['undefined_argument()'] * count) + ');')
    disabled.append('}')
    with tempfile.TemporaryDirectory(prefix='rpi-sdt-') as d:
        c = Path(d) / 'disabled.c'
        c.write_text('\n'.join(disabled))
        subprocess.run(['cc', '-D_KERNEL', '-Werror', '-fsyntax-only', str(c)], check=True)
    dtrace = shutil.which('dtrace')
    if dtrace is None:
        raise RuntimeError('dtrace is required to validate the installed script')
    subprocess.run([dtrace, '-e', '-s', str(ROOT / 'share/dtrace/rpi-wifi')], check=True)
    print(f'PASS: {len(definitions)} SDT probe schemas, disabled probes and DTrace script compilation')


if __name__ == '__main__':
    declarations_test()
    run_test('dtrace_sdio_test.c', [
        ('sys/compat/linuxkpi/common/src/linux_sdio.c', result, name)
        for result, name in [('static int', 'lkpi_sdio_attach'),
                             ('static void', 'lkpi_sdio_irq_task')]
    ])
    # The callback frees its firmware before callback-done. ASan detects any
    # instrumentation that accidentally reads the released allocation.
    run_test('firmware_test.c', [
        ('sys/compat/linuxkpi/common/src/linux_firmware.c', result, name)
        for result, name in [('static int', 'lkpi_fw_module_hold'),
                             ('static void', 'lkpi_fw_module_put'),
                             ('static int', '_linuxkpi_request_firmware'),
                             ('static void', 'lkpi_fw_task'),
                             ('int', 'linuxkpi_request_firmware_nowait')]
    ], ['-fsanitize=address', '-fno-omit-frame-pointer'])

    run_test('dtrace_scan_test.c', [
        ('sys/compat/linuxkpi/common/src/linux_80211_fullmac.c',
         'static void', 'lkpi_fullmac_scan_start')
    ], ['-fsanitize=address', '-fno-omit-frame-pointer'])
