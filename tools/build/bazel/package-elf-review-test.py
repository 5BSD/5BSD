# SPDX-License-Identifier: BSD-2-Clause
"""Bounded regression cases for the reviewer's archive streaming boundary."""
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import tempfile
import unittest


def module():
    spec = importlib.util.spec_from_file_location('package_elf_review', Path(__file__).with_name('package-elf-review.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def worker(request):
    config = json.loads(Path(request).read_text())
    root = Path(config['root'])
    try:
        selected, counts = module().materialize(root/'fixture.tar', root/'selected',
            {'/payload': {'tags': []}}, root/'producer', root/'stderr')
        assert selected['/payload'][0].read_bytes() == b'\x7fELF' + b'x' * 131072
        print(json.dumps(dict(counts=counts)))
        return 0
    except ValueError as error:
        print(str(error))
        return 2


class StreamingBoundary(unittest.TestCase):
    def check_case(self, *, duplicate=False, name='payload', trailer=b'', error=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'selected').mkdir()
            with tarfile.open(root/'fixture.tar', 'w') as archive:
                info = tarfile.TarInfo(name)
                payload = b'\x7fELF' + b'x' * 131072
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
                if duplicate:
                    archive.addfile(info, io.BytesIO(payload))
            # A valid tar stream with more trailing padding than a pipe can hold
            # exposed wait-before-drain. This fixture tests the review tool only.
            with (root/'fixture.tar').open('ab') as output:
                output.write(bytes(131072) + trailer)
            producer = root/'producer'
            producer.write_text('#!' + sys.executable + '\n'
                'import shutil, sys\n'
                'with open(sys.argv[-1][1:], "rb") as source:\n'
                '    shutil.copyfileobj(source, sys.stdout.buffer)\n')
            producer.chmod(0o700)
            request = root/'request.json'
            request.write_text(json.dumps(dict(root=str(root))))
            child = subprocess.Popen([sys.executable, '-B', __file__, '--worker', str(request)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
            try:
                stdout, stderr = child.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.communicate()
                self.fail('streaming review blocked on its producer pipe')
            if error is None:
                self.assertEqual(child.returncode, 0, stderr + stdout)
                self.assertEqual(json.loads(stdout)['counts']['elf'], 1)
            else:
                self.assertEqual(child.returncode, 2, stderr + stdout)
                self.assertIn(error, stdout)
            self.assertFalse((root/'payload').exists())

    def test_padding_larger_than_pipe_is_drained(self):
        self.check_case()

    def test_nonzero_trailing_data_is_rejected(self):
        self.check_case(trailer=b'not padding', error='nonzero archive conversion trailing data')

    def test_duplicate_members_are_rejected(self):
        self.check_case(duplicate=True, error='duplicate archive path')

    def test_traversal_is_rejected_without_extraction(self):
        self.check_case(name='../payload', error='noncanonical archive path')


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--worker':
        raise SystemExit(worker(sys.argv[2]))
    unittest.main()
