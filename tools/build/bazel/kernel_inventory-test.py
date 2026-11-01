#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import shutil
import os
import tempfile
import unittest
from pathlib import Path

from kernel_inventory import audit, describe, link_objects, VARIABLES


class KernelInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.build = self.root / 'objects'
        (self.source / 'sys/kern').mkdir(parents=True)
        (self.source / 'share/mk').mkdir(parents=True)
        (self.source / 'share/mk/sys.mk').write_text('# no implicit fixture rules\n')
        self.build.mkdir()
        for name in ('ordinary.c', 'locore.S', 'bus_if.m'):
            (self.source / 'sys/kern' / name).write_text('/* inventory fixture */\n')
        self.values = dict.fromkeys(VARIABLES, '')
        self.values.update({
            '.CURDIR': str(self.build), '.OBJDIR': str(self.build),
            'S': str(self.source / 'sys'), 'KERN_IDENT': 'EXAMPLE',
            'MACHINE': 'arm64', 'MACHINE_ARCH': 'aarch64',
            'CFILES': str(self.source / 'sys/kern/ordinary.c'),
            'SFILES': str(self.source / 'sys/kern/locore.S'),
            'GEN_CFILES': 'bus_if.c',
            'MFILES': str(self.source / 'sys/kern/bus_if.m'),
            'SYSTEM_OBJS': 'locore.o ordinary.o bus_if.o custom.o firmware.fwo',
            'SYSTEM_LD_BASECMD': 'ld -m example -T example.ld',
            'SYSTEM_LD': '@ld -m example -T example.ld -o locore.o ordinary.o bus_if.o custom.o firmware.fwo version.o',
        })
        (self.build / 'Makefile').write_text('# fixture\n')

    def test_final_link_keeps_generated_custom_firmware_and_version_products(self):
        report = describe(self.values, self.source, self.build)
        self.assertEqual([p['object'] for p in report['ordered_link_products']],
                         ['locore.o', 'ordinary.o', 'bus_if.o', 'custom.o', 'firmware.fwo', 'version.o'])
        self.assertEqual(report['final_link_additions'], ['version.o'])
        self.assertEqual(report['unresolved_products'], ['custom.o', 'firmware.fwo', 'version.o'])
        self.assertEqual(report['missing_generated_files'], [str(self.build / 'bus_if.c')])
        self.assertEqual(report['ordered_link_products'][2]['binding'], 'unique')
        self.assertIsNone(report['source_files'][str(self.build / 'bus_if.c')]['sha256'])

    def test_architecture_specific_link_arguments_are_retained(self):
        self.values['SYSTEM_LD'] = self.values['SYSTEM_LD'].replace(' -o ', ' "--defsym=text_start=kernbase + SIZEOF_HEADERS" -o ')
        report = describe(self.values, self.source, self.build)
        self.assertEqual(report['extra_link_arguments'], ['--defsym=text_start=kernbase + SIZEOF_HEADERS'])
        self.assertEqual(len(report['ordered_link_products']), 6)

    def test_arm_mapping_symbol_strip_is_retained_as_post_link_command(self):
        self.values['SYSTEM_LD'] += "; objcopy --wildcard --strip-symbol='$[adtx]*' ${.TARGET}"
        report = describe(self.values, self.source, self.build)
        self.assertEqual(report['post_link_tokens'], [';', 'objcopy', '--wildcard', '--strip-symbol=$[adtx]*', '${.TARGET}'])
        self.assertEqual(report['final_link_additions'], ['version.o'])
        self.assertEqual(len(report['ordered_link_products']), 6)

    def test_ambiguous_source_basename_is_not_silently_selected(self):
        other = self.source / 'sys/other/ordinary.c'
        other.parent.mkdir()
        other.write_text('/* different source */\n')
        self.values['CFILES'] += ' ' + str(other)
        report = describe(self.values, self.source, self.build)
        self.assertEqual(report['ordered_link_products'][1]['binding'], 'ambiguous')
        self.assertIn('ordinary.o', report['unresolved_products'])

    def test_missing_physical_source_is_an_error(self):
        (self.source / 'sys/kern/ordinary.c').unlink()
        with self.assertRaisesRegex(ValueError, 'physical source is missing'):
            describe(self.values, self.source, self.build)

    def test_relative_config_source_root_is_resolved_in_kernel_object_directory(self):
        self.values['S'] = os.path.relpath(self.source / 'sys', self.build)
        report = describe(self.values, self.source, self.build)
        self.assertEqual(report['kernel_identity'], 'EXAMPLE')

    def test_wrong_object_root_is_an_error(self):
        self.values['.OBJDIR'] = str(self.source)
        with self.assertRaisesRegex(ValueError, 'unexpected .OBJDIR'):
            describe(self.values, self.source, self.build)

    def test_changed_final_link_order_or_unknown_token_is_an_error(self):
        self.values['SYSTEM_LD'] = self.values['SYSTEM_LD'].replace('locore.o ordinary.o', 'ordinary.o locore.o')
        with self.assertRaisesRegex(ValueError, 'preserve SYSTEM_OBJS'):
            link_objects(self.values)
        self.values['SYSTEM_LD'] = '@ld -m example -T example.ld -o ' + self.values['SYSTEM_OBJS'] + ' unexpected-token'
        with self.assertRaisesRegex(ValueError, 'unrecognized final-link'):
            link_objects(self.values)

    def test_real_bsd_make_query_observes_configured_architecture_without_overriding_it(self):
        if 'TEST_SRCDIR' in os.environ:
            make = str(Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE'] / 'usr.bin/bmake/make')
            self.assertTrue(Path(make).is_file(), 'declared native bmake runfile required')
        else:
            make = shutil.which('make')
            self.assertIsNotNone(make, 'BSD Make is required for this independent migration audit')
        self.values['SYSTEM_LD'] = '@${SYSTEM_LD_BASECMD} -o ${.TARGET} ${SYSTEM_OBJS} version.o'
        lines = [key + '=' + value for key, value in self.values.items() if not key.startswith('.')]
        lines += ['all: ordinary.o', '\t@echo must-not-execute > query-executed']
        (self.build / 'Makefile').write_text('\n'.join(lines) + '\n')
        report = audit(self.source, self.build, 'arm64', 'aarch64', make=make)
        self.assertEqual(len(report['ordered_link_products']), 6)
        self.assertFalse((self.build / 'query-executed').exists())
        self.assertNotIn('MACHINE=arm64', report['command'])
        with self.assertRaisesRegex(ValueError, 'architecture does not match'):
            audit(self.source, self.build, 'amd64', 'amd64', make=make)


if __name__ == '__main__':
    unittest.main()
