#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise physical alias semantics and reject escapes before tool execution."""
import gzip
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from generate_man_database import generate


class DatabaseTest(unittest.TestCase):
    def test_real_index_aliases_and_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tool = root / 'makewhatis'
            tool.symlink_to((Path.cwd() / 'usr.bin/mandoc/makewhatis_execution').resolve(strict=True))
            query = root / 'apropos'
            query.symlink_to(tool)
            page = root / 'page.gz'
            page.write_bytes(gzip.compress(b'.Dd November 5, 2026\n.Dt ALPHA 1\n.Os\n.Sh NAME\n.Nm alpha\n.Nd indexed alias demonstration\n', mtime=0))
            prefix = '/usr/share/man/'
            records = [dict(destination=prefix+'man1/alpha.1.gz', type='file', source=str(page))]
            for name, kind, target in [('beta', 'hardlink', prefix+'man1/alpha.1.gz'),
                                       ('gamma', 'hardlink', prefix+'man1/beta.1.gz'),
                                       ('delta', 'symlink', 'gamma.1.gz'),
                                       ('epsilon', 'symlink', 'delta.1.gz')]:
                records.append(dict(destination=prefix+'man1/'+name+'.1.gz', type=kind, link=target))
            request = dict(root=prefix.rstrip('/'), records=records,
                hardlink_roots={prefix+'man1/'+name+'.1.gz':prefix+'man1/alpha.1.gz' for name in ['beta','gamma']})
            output = root/'result/mandoc.db'
            generate(request, tool, output)
            self.assertEqual([p.name for p in output.parent.iterdir()], ['mandoc.db'])
            # apropos validates indexed file paths against the installed corpus.
            pages = output.parent / 'man1'
            pages.mkdir()
            (pages/'alpha.1.gz').write_bytes(page.read_bytes())
            os.link(pages/'alpha.1.gz', pages/'beta.1.gz')
            os.link(pages/'beta.1.gz', pages/'gamma.1.gz')
            (pages/'delta.1.gz').symlink_to('gamma.1.gz')
            (pages/'epsilon.1.gz').symlink_to('delta.1.gz')
            for name in ['alpha', 'beta', 'gamma', 'delta', 'epsilon']:
                result = subprocess.run([str(query), '-C', '/dev/null', '-M', str(output.parent), name],
                    text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('indexed alias demonstration', result.stdout)

    def test_reject_escaping_dangling_and_cyclic_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root/'source'; source.write_text('manual')
            base = dict(destination='/usr/share/man/man1/a.1', type='file', source=str(source))
            for target in ['/etc/passwd', '../../../etc/passwd', 'missing.1', 'b.1']:
                with self.subTest(target=target):
                    request=dict(root='/usr/share/man', records=[base,
                        dict(destination='/usr/share/man/man1/b.1', type='symlink', link=target)], hardlink_roots={})
                    with self.assertRaises((ValueError, RuntimeError, FileNotFoundError)):
                        generate(request, root/'must-not-execute', root/'result/mandoc.db')
                    self.assertEqual(list((root/'result').iterdir()), [])

    def test_reject_invalid_destinations_and_hardlink_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for record, hardlinks in [
                (dict(destination='/usr/share/man/../escape', type='file', source='unused'), {}),
                (dict(destination='/usr/share/man/mandoc.db', type='file', source='unused'), {}),
                (dict(destination='/usr/share/man/a.1', type='hardlink', link='/etc/passwd'), {'/usr/share/man/a.1':'/etc/passwd'}),
            ]:
                with self.subTest(record=record), self.assertRaises(ValueError):
                    generate(dict(root='/usr/share/man', records=[record], hardlink_roots=hardlinks),
                        root/'must-not-execute', root/'result/mandoc.db')


if __name__ == '__main__':
    unittest.main()
