#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise NLS export using the maintained Make rules and temporary sources."""
from pathlib import Path
import subprocess
import tempfile
import unittest
import configured_nls
import file_install


class Catalogues(unittest.TestCase):
    def configured(self, declarations, check):
        with tempfile.TemporaryDirectory(prefix='nls-metadata-') as temporary:
            root = Path(temporary)
            (root / 'messages').mkdir()
            for name in ('a.msg', 'b.msg', 'sample.msg'):
                (root / 'messages' / name).write_text('$set 1\n1 example\n')
            (root / 'Makefile').write_text('''NLS= sample
NLSNAME= example
NLSPACKAGE= locales
GENCAT= /usr/bin/true
.PATH: ${.CURDIR}/messages
''' + declarations + '''
.include <bsd.init.mk>
.include <bsd.nls.mk>
.include <bsd.files.mk>
''')
            mk = Path(__file__).resolve().parents[3] / 'share/mk'
            def query(component, keys, extra=()):
                result = subprocess.run(['/usr/bin/make', '-m', str(mk),
                                         'NO_ROOT=yes', 'DB_FROM_SRC=yes', 'BUILD_PKGS=yes',
                                         *extra, *[v for k in keys for v in ('-V', k)]],
                                        cwd=component, check=True, text=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                rows = result.stdout.splitlines()
                self.assertEqual(len(rows), len(keys))
                return dict(zip(keys, rows))
            inputs = {}
            check(root, query, inputs)

    def test_source_catalogue_and_effective_installation(self):
        def check(root, query, inputs):
            record = configured_nls.export(root, root, query, [], inputs)
            self.assertEqual(record['outputs'], [dict(name='sample.cat', concatenate=False,
                sources=[dict(path='messages/sample.msg', sha256=inputs[str(root/'messages/sample.msg')])])])
            files = {}
            def add(path, *args, **details):
                self.assertNotIn(path, files)
                files[path] = (args, details)
            file_install.export(query(root, ['FILESGROUPS']), lambda keys: query(root, keys),
                                add, lambda name: dict(output=name))
            self.assertEqual(set(files), {'/usr/share/nls/sample/example.cat'})
            args, details = next(iter(files.values()))
            self.assertEqual(details, dict(role='file', output='sample.cat'))
            self.assertIn('package=locales', args[-1])
        self.configured('', check)

    def test_concatenated_sources_preserve_order(self):
        def check(root, query, inputs):
            record = configured_nls.export(root, root, query, [], inputs)
            output = record['outputs'][0]
            self.assertTrue(output['concatenate'])
            self.assertEqual([s['path'] for s in output['sources']], ['messages/b.msg', 'messages/a.msg'])
        self.configured('NLSSRCFILES= b.msg a.msg\nNLSSRCDIR= ${.CURDIR}/messages\n', check)

    def test_disabled_nls_has_no_generator(self):
        self.configured('MK_NLS= no\n', lambda root, query, inputs:
                        self.assertIsNone(configured_nls.export(root, root, query, [], inputs)))

    def test_tool_arguments_rejected(self):
        def check(root, query, inputs):
            with self.assertRaisesRegex(ValueError, 'one executable'):
                configured_nls.export(root, root, query, [], inputs)
        self.configured('GENCAT= /usr/bin/true --unexpected\n', check)


if __name__ == '__main__':
    unittest.main()
