import os
from pathlib import Path
import tempfile
import unittest
from input_evidence import snapshot_inputs


class InputEvidenceTests(unittest.TestCase):
    def test_content_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'lib').mkdir()
            binary = root / 'lib' / 'runtime'
            binary.write_bytes(b'first')
            first = snapshot_inputs(root)
            binary.write_bytes(b'other')
            second = snapshot_inputs(root)
            self.assertNotEqual(first['entries']['lib/runtime']['sha256'],
                                second['entries']['lib/runtime']['sha256'])
            self.assertEqual(second['entries']['lib/runtime']['size'], 5)

    def test_links_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / 'root'
            root.mkdir()
            outside = parent / 'outside'
            outside.mkdir()
            (outside / 'file').write_text('outside content')
            link = root / 'link'
            link.symlink_to(outside, target_is_directory=True)
            first = snapshot_inputs(root)
            self.assertEqual(set(first['entries']), {'link'})
            self.assertEqual(first['entries']['link'],
                             {'type': 'symlink', 'target': str(outside)})
            link.unlink()
            link.symlink_to('missing')
            self.assertNotEqual(first, snapshot_inputs(root))

    def test_special_file_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            os.mkfifo(Path(directory) / 'fifo')
            with self.assertRaisesRegex(ValueError, 'unsupported staged input type'):
                snapshot_inputs(directory)


if __name__ == '__main__':
    unittest.main()
