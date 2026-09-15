#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Test pinned downloader cache validation and failure without network access."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('rpi_fetch', ROOT/'release/tools/fetch-rpi-wifi-firmware.py')
fetcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetcher)
with tempfile.TemporaryDirectory(prefix='rpi-fetch-test-') as directory:
    work = Path(directory)
    manifest = work/'firmware.tsv'
    content = {'pi4.bin': b'pi4 firmware', 'zero2.bin': b'zero2 firmware', 'COPYRIGHT': b'license'}
    manifest.write_text('\n'.join('\t'.join((owner, name, hashlib.sha256(content[name]).hexdigest(), name))
        for owner, name in [('rpi4','pi4.bin'),('rpi-zero2','zero2.bin'),('all','COPYRIGHT')]))
    fetcher.MANIFEST = manifest
    dest = work/'cache'
    def serve(url, timeout):
        assert fetcher.REVISION in url and timeout > 0
        return io.BytesIO(content[url.rsplit('/',1)[1]])
    with patch.object(fetcher.urllib.request, 'urlopen', side_effect=serve) as request:
        fetcher.fetch(dest, 'rpi4')
        assert request.call_count == 2
        assert not (dest/'zero2.bin').exists()
    with patch.object(fetcher.urllib.request, 'urlopen', side_effect=AssertionError('cache contacted network')):
        fetcher.fetch(dest, 'rpi4')
    target = dest/'pi4.bin'
    target.write_bytes(b'old damaged file')
    with patch.object(fetcher.urllib.request, 'urlopen', return_value=io.BytesIO(b'bad download')):
        try:
            fetcher.fetch(dest, 'rpi4')
        except ValueError as error:
            assert 'checksum mismatch' in str(error)
        else:
            raise AssertionError('bad firmware accepted')
    assert target.read_bytes() == b'old damaged file'
    with patch.object(fetcher.urllib.request, 'urlopen', side_effect=TimeoutError):
        try:
            fetcher.fetch(dest, 'rpi4')
        except TimeoutError:
            pass
        else:
            raise AssertionError('network failure ignored')
    assert target.read_bytes() == b'old damaged file'
    assert not list(dest.glob('*.tmp'))
    with patch.object(fetcher.urllib.request, 'urlopen', side_effect=serve):
        fetcher.fetch(dest, 'all')
    assert all((dest/name).read_bytes() == data for name,data in content.items())
print('PASS: board selection, verified offline cache, corrupt download, timeout and cache repair')
