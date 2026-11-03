# SPDX-License-Identifier: BSD-2-Clause
"""Actual native action versus the original nm/elfcopy recipe; not a boot test."""
import argparse
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

parser = argparse.ArgumentParser()
for name in ('source', 'unresolved', 'application', 'future', 'raw', 'helper', 'objcopy', 'nm', 'strip'):
    parser.add_argument('--' + name, required=True, type=Path)
parser.add_argument('--strip-inputs', nargs='*', type=Path, default=[])
parser.add_argument('--objcopy-runtime', required=True, nargs='+', type=Path)
args, remaining = parser.parse_known_args()
sys.argv[1:] = remaining
SECTIONS = ['.peheader', '.text', '.sdata', '.data', '.dynamic', '.dynsym',
            '.rel.dyn', '.rela.dyn', '.reloc', '.eh_frame']


def converter_environment(epoch):
    return {'LC_ALL': 'C', 'SOURCE_DATE_EPOCH': str(epoch),
            'LD_LIBRARY_PATH': ':'.join(sorted({str(p.resolve(strict=True).parent) for p in args.objcopy_runtime}))}


class EfiConversion(unittest.TestCase):
    def compare_recipe(self, image, format, epoch):
        with tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR']) as temporary:
            output = Path(temporary) / 'original-image'
            # Original boot1/loader recipe, without the new Python adapter.
            check = subprocess.run([str(args.nm), str(args.source)], capture_output=True, text=True,
                                   env={'LC_ALL': 'C'}, check=True)
            self.assertNotIn(' U ', check.stdout)
            command = [str(args.objcopy)]
            for section in SECTIONS:
                command += ['-j', section]
            command += ['--output-target=' + format, str(args.source), str(output)]
            subprocess.run(command, env=converter_environment(epoch), check=True, capture_output=True)
            self.assertEqual(image.read_bytes(), output.read_bytes())
            self.assertNotIn(b'excluded EFI fixture payload', image.read_bytes())

    def inspect_application(self, image, timestamp):
        data = image.read_bytes()
        self.assertEqual(data[:2], b'MZ')
        offset = struct.unpack_from('<I', data, 0x3c)[0]
        self.assertLessEqual(offset + 96, len(data))
        self.assertEqual(data[offset:offset + 4], b'PE\0\0')
        self.assertEqual(struct.unpack_from('<H', data, offset + 4)[0], 0x8664)
        self.assertEqual(struct.unpack_from('<I', data, offset + 8)[0], timestamp)
        self.assertEqual(struct.unpack_from('<H', data, offset + 24)[0], 0x20b)
        self.assertEqual(struct.unpack_from('<H', data, offset + 24 + 68)[0], 10)

    def test_application_matches_original_recipe(self):
        self.compare_recipe(args.application, 'efi-app-x86_64', 1704067200)
        self.inspect_application(args.application, 1704067200)

    def test_unsigned_timestamp_beyond_2038(self):
        self.compare_recipe(args.future, 'efi-app-x86_64', 2147483649)
        self.inspect_application(args.future, 2147483649)
        self.assertNotEqual(args.application.read_bytes(), args.future.read_bytes())

    def test_raw_section_copy_matches_original_recipe(self):
        self.compare_recipe(args.raw, 'binary', 1704067200)

    def helper(self, source, output, epoch='1704067200'):
        command = [sys.executable, '-B', str(args.helper), '--src', str(source), '--output', str(output),
                   '--nm', str(args.nm), '--objcopy', str(args.objcopy), '--format', 'efi-app-x86_64', '--epoch', epoch]
        for section in SECTIONS:
            command += ['--section', section]
        command += ['--objcopy-runtime', *map(str, args.objcopy_runtime)]
        return subprocess.run(command, capture_output=True, text=True, timeout=15)

    def test_undefined_symbol_rejects_stale_output(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR']) as temporary:
            output = Path(temporary) / 'rejected.efi'
            output.write_bytes(b'stale successful output')
            result = self.helper(args.unresolved, output)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Undefined symbols', result.stderr)
            self.assertIn('missing_firmware_entry', result.stderr)
            self.assertFalse(output.exists())

    def test_stripped_dynamic_undefined_symbol_rejected(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR']) as temporary:
            source = Path(temporary) / 'stripped.sym'
            output = Path(temporary) / 'rejected.efi'
            strip_env = {'LC_ALL': 'C'}
            strip_runtime = [p for p in args.strip_inputs if p.resolve(strict=True) != args.strip.resolve(strict=True)]
            if strip_runtime:
                strip_env['LD_LIBRARY_PATH'] = ':'.join(sorted({str(p.resolve(strict=True).parent)
                                                               for p in strip_runtime}))
            subprocess.run([str(args.strip), '--strip-all', '-o', str(source), str(args.unresolved)],
                           env=strip_env, check=True, capture_output=True)
            ordinary = subprocess.run([str(args.nm), '--undefined-only', str(source)],
                                      env={'LC_ALL': 'C'}, check=True, capture_output=True, text=True)
            self.assertNotIn('missing_firmware_entry', ordinary.stdout)
            result = self.helper(source, output)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Undefined symbols', result.stderr)
            self.assertIn('missing_firmware_entry', result.stderr)
            self.assertFalse(output.exists())

    def test_in_place_conversion_preserves_source(self):
        before = hashlib.sha256(args.source.read_bytes()).hexdigest()
        result = self.helper(args.source, args.source)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('input and output must differ', result.stderr)
        self.assertEqual(hashlib.sha256(args.source.read_bytes()).hexdigest(), before)

    def test_out_of_range_timestamp_rejected(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR']) as temporary:
            for epoch in ['-1', '4294967296', 'not-a-timestamp']:
                output = Path(temporary) / 'bad.efi'
                result = self.helper(args.source, output, epoch)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('unsigned PE timestamp', result.stderr)
                self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
