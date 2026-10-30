#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Ensure runtime checks visit dependencies reachable only through GROUP."""
import unittest
import tempfile
import json
from pathlib import Path
import native_c_tests
from configured_tests import runtime_libraries


def library(name, dependencies=(), shared=True):
    return dict(component='lib/'+name, metadata=dict(LIB=name, LIB_PRIVATE='',
        LIBADD=' '.join(dependencies), LDADD=' '.join('-l'+d for d in dependencies),
        SHLIB_NAME='lib'+name+'.so.1' if shared else '',
        _LIBS='lib'+name+'.a'+(' lib'+name+'.so.1' if shared else '')),
        library_dependencies=[dict(name=d,component='lib/'+d,ldadd=['-l'+d],
            dpadd=['/usr/obj/lib'+d+'.a']) for d in dependencies])


class RuntimeGroups(unittest.TestCase):
    def setUp(self):
        self.program=library('', ['owner'], False)
        self.owner=library('owner')
        self.owner['shared_link_script']={'template': 'resolved separately'}
        self.archive=library('group_only', ['runtime'])
        self.runtime=library('runtime')
        self.components=[self.program,self.owner,self.archive,self.runtime]
        self.groups={'lib/owner':[dict(component='lib/owner',library='owner',kind='shared',variant=None),
            dict(component='lib/group_only',library='group_only',kind='archive',variant='regular')]}

    def test_group_only_archive_dependency_is_checked(self):
        result=runtime_libraries(self.program,self.components,groups=self.groups)
        self.assertEqual(set(result),{'libowner.so.1','libruntime.so.1'})
        self.assertNotIn('libgroup_only.so.1',result)

    def test_shared_group_member_is_checked(self):
        self.groups['lib/owner'][1]=dict(component='lib/group_only',library='group_only',kind='shared',variant=None)
        result=runtime_libraries(self.program,self.components,groups=self.groups)
        self.assertEqual(set(result),{'libowner.so.1','libgroup_only.so.1','libruntime.so.1'})

    def test_native_consumer_uses_same_group_closure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);src=root/'src';src.mkdir();out=root/'workspace';out.mkdir()
            (src/'main.c').write_text('int main(void) { return 0; }\n')
            config=root/'tests.json'
            config.write_text(json.dumps(dict(format=1,suite='native-c',tests=[dict(
                name='consumer',source='main.c',dependencies=['owner'],cflags=[],linkage='dynamic')])))
            data=dict(components=self.components,build_environment=dict(objtop='/usr/obj'))
            native_c_tests.emit(out,data,config,src,groups=self.groups)
            receipt=json.loads((out/'native-test-inventory.json').read_text())
            self.assertEqual(set(receipt['runtime_checks'][0]['libraries']),
                             {'libowner.so.1','libruntime.so.1'})

    def test_group_catalogue_uses_source_identity(self):
        # A second library with the same basename has a different GROUP.
        # Its catalogue entry must not replace this program's selected GROUP.
        import copy
        other=copy.deepcopy(self.owner)
        other['component']='stand/owner'
        self.components.append(other)
        self.groups['stand/owner']=[dict(component='stand/owner',library='owner',kind='shared',variant=None)]
        result=runtime_libraries(self.program,self.components,groups=self.groups)
        self.assertEqual(set(result),{'libowner.so.1','libruntime.so.1'})
        self.assertEqual(result['libowner.so.1']['component'],'lib/owner')
        del self.groups['lib/owner']
        with self.assertRaisesRegex(ValueError,'runtime GROUP inventory missing'):
            runtime_libraries(self.program,self.components,groups=self.groups)

    def test_missing_group_inventory_rejected(self):
        with self.assertRaisesRegex(ValueError,'runtime GROUP inventory missing'):
            runtime_libraries(self.program,self.components)

if __name__=='__main__':unittest.main()
