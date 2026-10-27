# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the production media hints backend without installing packages."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location('hardware', '/usr/src/release/scripts/hardware-packages.py')
hardware = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hardware)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    with tempfile.TemporaryDirectory(prefix='media-hints-', dir='/tmp') as temporary:
        base = Path(temporary)
        tool = Path('/usr/sbin/kldxref')
        for value in (None, Path('kldxref'), base):
            try:
                hardware.hints_generator(value)
            except ValueError:
                pass
            else:
                raise AssertionError('invalid generator accepted')
        media = base / 'media'
        modules = media / 'boot/modules'; modules.mkdir(parents=True)
        shutil.copyfile('/tests/selected.ko', modules / 'selected.ko')
        shadow = base / 'shadow'; shadow.mkdir()
        trap = shadow / 'kldxref'; trap.write_text('#!/bin/sh\nexit 87\n'); trap.chmod(0o755)
        before_path = os.environ['PATH']
        try:
            os.environ['PATH'] = str(shadow) + ':' + before_path
            hardware.install_live_firmware(media, base, '/unused-pkg', {'packages': {}}, tool)
        finally:
            os.environ['PATH'] = before_path
        hints = modules / 'linker.hints'
        before = hints.read_bytes()
        metalog = (media / 'METALOG').read_bytes()
        require(bool(before) and b'linker.hints' in metalog, 'index or METALOG missing')
        (modules / 'malformed.ko').write_bytes(b'not ELF\n')
        try:
            hardware.install_live_firmware(media, base, '/unused-pkg', {'packages': {}}, tool)
        except subprocess.CalledProcessError:
            pass
        else:
            raise AssertionError('malformed media module accepted')
        require(hints.read_bytes() == before, 'failed generator replaced prior hints')
        require((media / 'METALOG').read_bytes() == metalog, 'failed generator appended metadata')
        require(not list(modules.glob('lhint.*')), 'temporary output survived')
        print('CONSTRUCTION_VM_PASS media_generator_binding', flush=True)


if __name__ == '__main__':
    main()
