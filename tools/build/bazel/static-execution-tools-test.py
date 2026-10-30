#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Native rejection controls for the static execution-tool builder."""
import argparse
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('builder',Path(__file__).with_name('static-execution-tools.py'))
builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--static-binary',type=Path,required=True)
args=parser.parse_args()

class Guards(unittest.TestCase):
    def test_make_expansion_and_control_paths(self):
        for value in ('/usr/obj/$bad','/usr/obj/bad\nname','relative'):
            with self.assertRaisesRegex(ValueError,'absolute paths'):builder.checked_path(Path(value),False)

    def test_output_reuse_and_sdk_rejected(self):
        for output in ('/usr/obj','/usr/obj/usr/src/amd64.amd64/tmp/new-static-tools','/usr/src/obj/new-static-tools','/tmp/new-static-tools'):
            with self.assertRaisesRegex(ValueError,'output must be fresh'):builder.output_path(Path(output),Path('/usr/src'),Path('/usr/obj/usr/src/amd64.amd64'))

    def test_output_symlink_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'alias').symlink_to('/tmp')
            with self.assertRaisesRegex(ValueError,'output must be fresh'):builder.output_path(root/'alias/new-static-tools',Path('/usr/src'),Path('/usr/obj/usr/src/amd64.amd64'))
            self.assertFalse((root/'alias/new-static-tools').exists())

    def test_duplicate_and_escaping_selection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);src=root/'src';(src/'bin/tool').mkdir(parents=True);(src/'bin/tool/Makefile').write_text('PROG=tool\n');config=root/'tools.json'
            config.write_text('{"format":1,"tools":{"tool":{"component":"bin/tool","binary":"tool"},"tool":{}}}')
            with self.assertRaisesRegex(ValueError,'duplicate JSON key'):builder.selection(config,src)
            for value in ('../outside','/absolute','bin/../outside','bin//tool','$bad'):
                config.write_text(json.dumps({'format':1,'tools':{'tool':{'component':value,'binary':'tool'}}}))
                with self.assertRaises(ValueError):builder.selection(config,src)
            (src/'escape').symlink_to(root,target_is_directory=True)
            config.write_text(json.dumps({'format':1,'tools':{'tool':{'component':'escape','binary':'tool'}}}))
            with self.assertRaisesRegex(ValueError,'maintained source'):builder.selection(config,src)
            config.write_text(json.dumps({'format':1,'tools':{'tool':{'component':'bin/tool','binary':'../../escape'}}}))
            with self.assertRaisesRegex(ValueError,'normalized relative'):builder.selection(config,src)

    def test_real_static_and_dynamic_elf(self):
        result=builder.static_elf(args.static_binary.resolve(strict=True),Path('/usr/bin/readelf'))
        self.assertEqual(result['status'],0)
        with self.assertRaisesRegex(ValueError,'without PT_INTERP/DT_NEEDED'):builder.static_elf(Path('/bin/sh'),Path('/usr/bin/readelf'))
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'script';path.write_text('#!/bin/sh\n');path.chmod(0o755)
            with self.assertRaisesRegex(ValueError,'not ELF'):builder.static_elf(path,Path('/usr/bin/readelf'))

unittest.main(argv=['static-execution-tools-test'])
